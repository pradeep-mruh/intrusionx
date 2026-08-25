"""
Integration and constraint tests for the IntrusionX Phase 2 domain data models.
"""

from datetime import datetime, timezone
import uuid
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.models import (
    AnalystAction,
    ConflictEvidence,
    Entity,
    EventEntityRef,
    Evidence,
    EvidenceConflict,
    EvidenceGap,
    GapEvent,
    Hypothesis,
    HypothesisElement,
    Investigation,
    NormalizedEvent,
    Reconstruction,
    ReconstructionStep,
    Relationship,
    RelationshipSupport,
)


@pytest_asyncio.fixture
async def db_session():
    """Provides a transactional database session for tests."""
    engine = create_async_engine(settings.database_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_full_investigation_domain_pipeline(db_session: AsyncSession):
    """
    Tests the complete IntrusionX lineage chain:
    Investigation -> Evidence -> NormalizedEvents -> Entities -> Relationship ->
    RelationshipSupport -> Gap & GapEvents -> Reconstruction & Steps ->
    Hypothesis & Elements -> Conflict & Evidence -> AnalystAction audit trail.
    """
    analyst_uuid = uuid.uuid4()

    # 1. Investigation
    inv = Investigation(
        title="APT-Mock Phishing Investigation",
        description="Investigation into suspicious macro execution on DC01",
        status="OPEN",
        created_by=analyst_uuid,
    )
    db_session.add(inv)
    await db_session.flush()
    assert inv.id is not None

    # 2. Raw Evidence (Preserved Source Record)
    evd = Evidence(
        investigation_id=inv.id,
        source_type="SYSMON",
        source_identifier="DC01_sysmon_20260825.evtx",
        original_content="<Event><System><EventID>1</EventID></System></Event>",
        content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        hash_algorithm="SHA-256",
        source_metadata={"collector": "winlogbeat", "version": "8.12.0"},
        is_immutable=True,
    )
    db_session.add(evd)
    await db_session.flush()
    assert evd.id is not None

    # 3. Normalized Events (Derived from Evidence)
    now = datetime.now(timezone.utc)
    evt_word = NormalizedEvent(
        investigation_id=inv.id,
        evidence_id=evd.id,
        occurred_at=now,
        event_type="PROCESS_CREATE",
        event_category="PROCESS",
        source_host="DC01",
        source_user="CORP\\alice",
        process_name="WINWORD.EXE",
        process_id="4812",
        action="EXECUTE",
        action_result="SUCCESS",
        extended_attributes={"command_line": '"C:\\Program Files\\Microsoft Office\\WINWORD.EXE" invoice.docm'},
    )
    evt_ps = NormalizedEvent(
        investigation_id=inv.id,
        evidence_id=evd.id,
        occurred_at=now,
        event_type="PROCESS_CREATE",
        event_category="PROCESS",
        source_host="DC01",
        source_user="CORP\\alice",
        process_name="powershell.exe",
        process_id="6104",
        parent_process_name="WINWORD.EXE",
        parent_process_id="4812",
        action="EXECUTE",
        action_result="SUCCESS",
        extended_attributes={"command_line": "powershell.exe -enc SQBFAFgA..."},
    )
    db_session.add_all([evt_word, evt_ps])
    await db_session.flush()

    # 4. Canonical Entities & Junction Refs
    host_entity = Entity(
        investigation_id=inv.id,
        entity_type="HOST",
        canonical_value="dc01.corp.local",
        attributes={"os": "Windows Server 2022"},
        first_seen_at=now,
        last_seen_at=now,
    )
    db_session.add(host_entity)
    await db_session.flush()

    ref_word = EventEntityRef(event_id=evt_word.id, entity_id=host_entity.id, role="SOURCE_HOST")
    ref_ps = EventEntityRef(event_id=evt_ps.id, entity_id=host_entity.id, role="SOURCE_HOST")
    db_session.add_all([ref_word, ref_ps])
    await db_session.flush()

    # 5. Relationship (with explicit typed FKs)
    rel = Relationship(
        investigation_id=inv.id,
        relationship_type="SPAWNED",
        source_event_id=evt_word.id,
        source_entity_id=None,
        target_event_id=evt_ps.id,
        target_entity_id=None,
        creation_method="PROCESS_PARENT_CHILD",
        status="SYSTEM_PROPOSED",
        explanation="WINWORD.EXE (PID 4812) spawned powershell.exe declaring parent PID 4812",
    )
    db_session.add(rel)
    await db_session.flush()

    # Relationship support
    sup_word = RelationshipSupport(relationship_id=rel.id, event_id=evt_word.id, support_reason="PARENT_PID_MATCH")
    sup_ps = RelationshipSupport(relationship_id=rel.id, event_id=evt_ps.id, support_reason="CHILD_PID_MATCH")
    db_session.add_all([sup_word, sup_ps])
    await db_session.flush()

    from datetime import timedelta
    # 6. Evidence Gap & GapEvent
    gap = EvidenceGap(
        investigation_id=inv.id,
        gap_start=now,
        gap_end=now + timedelta(seconds=79),
        description="Missing endpoint telemetry during 79s post-powershell execution window",
        status="OPEN",
    )
    db_session.add(gap)
    await db_session.flush()

    gap_pre = GapEvent(gap_id=gap.id, event_id=evt_ps.id, role="PRECEDING")
    db_session.add(gap_pre)
    await db_session.flush()

    # 7. Reconstruction & Ordered Steps
    rec = Reconstruction(
        investigation_id=inv.id,
        title="Initial Access via Malicious Macro",
        status="DRAFT",
    )
    db_session.add(rec)
    await db_session.flush()

    step1 = ReconstructionStep(reconstruction_id=rec.id, step_order=10, step_type="EVENT", event_id=evt_word.id)
    step2 = ReconstructionStep(reconstruction_id=rec.id, step_order=20, step_type="RELATIONSHIP", relationship_id=rel.id)
    step3 = ReconstructionStep(reconstruction_id=rec.id, step_order=30, step_type="EVENT", event_id=evt_ps.id)
    step4 = ReconstructionStep(reconstruction_id=rec.id, step_order=40, step_type="GAP", gap_id=gap.id)
    db_session.add_all([step1, step2, step3, step4])
    await db_session.flush()

    # 8. Hypothesis & HypothesisElements
    hyp = Hypothesis(
        investigation_id=inv.id,
        reconstruction_id=rec.id,
        title="Phishing macro execution leads to memory injection",
        status="SUPPORTED",
    )
    db_session.add(hyp)
    await db_session.flush()

    hyp_el1 = HypothesisElement(hypothesis_id=hyp.id, event_id=evt_word.id)
    hyp_el2 = HypothesisElement(hypothesis_id=hyp.id, relationship_id=rel.id)
    db_session.add_all([hyp_el1, hyp_el2])
    await db_session.flush()

    # 9. Evidence Conflict & ConflictEvidence
    conflict = EvidenceConflict(
        investigation_id=inv.id,
        conflict_type="CONTRADICTORY_TIMING",
        status="OPEN",
        description="Timestamp skew between Sysmon and Windows Security log",
    )
    db_session.add(conflict)
    await db_session.flush()

    conf_ev = ConflictEvidence(conflict_id=conflict.id, evidence_id=evd.id, event_id=evt_word.id)
    db_session.add(conf_ev)
    await db_session.flush()

    # 10. Analyst Action (Append-Only Confirmation)
    action = AnalystAction(
        investigation_id=inv.id,
        analyst_id=analyst_uuid,
        action_type="CONFIRM_RELATIONSHIP",
        target_object_type="RELATIONSHIP",
        target_object_id=rel.id,
        previous_state={"status": "SYSTEM_PROPOSED"},
        new_state={"status": "ANALYST_CONFIRMED"},
        reason="Verified parent process PID chain in memory dump",
    )
    rel.status = "ANALYST_CONFIRMED"
    rel.status_changed_at = datetime.now(timezone.utc)
    db_session.add(action)
    await db_session.commit()

    # 11. Verify Lineage Query
    stmt = (
        select(Relationship)
        .where(Relationship.id == rel.id)
    )
    result = await db_session.execute(stmt)
    loaded_rel = result.scalar_one()

    assert loaded_rel.status == "ANALYST_CONFIRMED"
    assert loaded_rel.source_event_id == evt_word.id
    assert loaded_rel.target_event_id == evt_ps.id


@pytest.mark.asyncio
async def test_relationship_mutual_exclusion_constraint(db_session: AsyncSession):
    """Tests that a Relationship with multiple source FKs violates the DB check constraint."""
    analyst_uuid = uuid.uuid4()
    inv = Investigation(title="Constraint Test Case", created_by=analyst_uuid)
    db_session.add(inv)
    await db_session.flush()

    evd = Evidence(
        investigation_id=inv.id,
        source_type="OTHER",
        source_identifier="test.log",
        original_content="dummy",
        content_hash=uuid.uuid4().hex,
    )
    db_session.add(evd)
    await db_session.flush()

    evt = NormalizedEvent(
        investigation_id=inv.id,
        evidence_id=evd.id,
        occurred_at=datetime.now(timezone.utc),
        event_type="TEST",
        event_category="OTHER",
    )
    ent = Entity(
        investigation_id=inv.id,
        entity_type="HOST",
        canonical_value="testhost",
    )
    db_session.add_all([evt, ent])
    await db_session.flush()

    # Attempt to populate both source_event_id and source_entity_id
    invalid_rel = Relationship(
        investigation_id=inv.id,
        relationship_type="INVALID",
        source_event_id=evt.id,
        source_entity_id=ent.id,  # Invalid: both source FKs set
        target_event_id=evt.id,
        target_entity_id=None,
        creation_method="TEST",
        status="SYSTEM_PROPOSED",
        explanation="Test",
    )
    db_session.add(invalid_rel)

    with pytest.raises(IntegrityError):
        await db_session.flush()
    await db_session.rollback()
