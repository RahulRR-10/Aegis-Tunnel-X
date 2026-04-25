import { useEffect, useMemo, useRef, useState } from 'react';

const DEFAULT_WS_URL =
  import.meta.env.VITE_AEGIS_WS_URL || 'ws://localhost:8765/ws/metrics';

const MAX_BUFFER_SIZE = 300;
const INITIAL_RECONNECT_MS = 1000;
const MAX_RECONNECT_MS = 30000;

export function useAegisSocket({
  url = DEFAULT_WS_URL,
  bufferSize = MAX_BUFFER_SIZE,
} = {}) {
  const [data, setData] = useState(null);
  const [history, setHistory] = useState([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState(null);
  const [status, setStatus] = useState('connecting');

  const socketRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const retryRef = useRef(0);
  const shouldReconnectRef = useRef(true);

  useEffect(() => {
    shouldReconnectRef.current = true;

    function clearReconnectTimer() {
      if (reconnectTimerRef.current) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
    }

    function scheduleReconnect() {
      if (!shouldReconnectRef.current) {
        return;
      }

      const delay = Math.min(
        INITIAL_RECONNECT_MS * 2 ** retryRef.current,
        MAX_RECONNECT_MS,
      );

      retryRef.current += 1;
      setConnected(false);
      setStatus(retryRef.current >= 3 ? 'dead' : 'reconnecting');

      clearReconnectTimer();
      reconnectTimerRef.current = window.setTimeout(connect, delay);
    }

    function connect() {
      if (!shouldReconnectRef.current) {
        return;
      }

      setStatus(retryRef.current === 0 ? 'connecting' : 'reconnecting');

      const socket = new WebSocket(url);
      socketRef.current = socket;

      socket.addEventListener('open', () => {
        retryRef.current = 0;
        setConnected(true);
        setError(null);
        setStatus('live');
      });

      socket.addEventListener('message', (event) => {
        try {
          const frame = JSON.parse(event.data);
          setData(frame);
          setHistory((previous) => {
            const next = previous.length >= bufferSize
              ? previous.slice(previous.length - bufferSize + 1)
              : previous.slice();
            next.push(frame);
            return next;
          });
        } catch (parseError) {
          setError(`Malformed WebSocket frame: ${parseError.message}`);
        }
      });

      socket.addEventListener('error', () => {
        setError('WebSocket connection failed');
      });

      socket.addEventListener('close', () => {
        if (socketRef.current === socket) {
          socketRef.current = null;
        }
        scheduleReconnect();
      });
    }

    connect();

    return () => {
      shouldReconnectRef.current = false;
      clearReconnectTimer();

      if (socketRef.current) {
        socketRef.current.close(1000, 'component unmounted');
        socketRef.current = null;
      }
    };
  }, [bufferSize, url]);

  return useMemo(
    () => ({ data, history, connected, error, status }),
    [connected, data, error, history, status],
  );
}
