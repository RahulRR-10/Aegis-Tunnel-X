"""Phase 4 placeholder for tunnel integration.

Will implement:
  - AegisTunnel (TUN ↔ UDP bidirectional glue)
  - _tun_to_udp coroutine (read TUN → morphic transform → transport send)
  - _udp_to_tun coroutine (transport receive → morphic detransform → write TUN)
  - Blocking TUN reads wrapped in loop.run_in_executor() for Windows
  - IP fragmentation and reassembly
  - packet_stats property for feedback loop
"""
