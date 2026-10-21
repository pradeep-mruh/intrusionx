import React from 'react';
import type { Event } from '../types/workspace';

export const EventTimeline: React.FC<{ events: Event[] }> = ({ events }) => {
  if (!events || events.length === 0) {
    return <div className="ws-empty">No events observed.</div>;
  }

  // Sort events chronologically
  const sortedEvents = [...events].sort((a, b) =>
    new Date(a.occurred_at).getTime() - new Date(b.occurred_at).getTime()
  );

  return (
    <div className="ws-card">
      {sortedEvents.map(event => (
        <div key={event.id} className="ws-event-row">
          <div className="ws-event-time">
            {new Date(event.occurred_at).toLocaleString([], {
              month: 'short',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
              hour12: false,
            })}
          </div>
          <div className="ws-event-type">{event.event_type}</div>
          <div className="ws-event-details">
            {event.process_name && (
              <div className="ws-event-detail">
                <span className="ws-detail-label">Process:</span>
                <span className="ws-detail-value">{event.process_name}</span>
              </div>
            )}
            {event.process_id && (
              <div className="ws-event-detail">
                <span className="ws-detail-label">PID:</span>
                <span className="ws-detail-value">{event.process_id}</span>
              </div>
            )}
            {event.source_user && (
              <div className="ws-event-detail">
                <span className="ws-detail-label">User:</span>
                <span className="ws-detail-value">{event.source_user}</span>
              </div>
            )}
            {event.file_path && (
              <div className="ws-event-detail">
                <span className="ws-detail-label">File:</span>
                <span className="ws-detail-value">{event.file_path}</span>
              </div>
            )}
            {event.destination_ip && (
              <div className="ws-event-detail">
                <span className="ws-detail-label">Dest:</span>
                <span className="ws-detail-value">{event.destination_ip}:{event.destination_port}</span>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};
