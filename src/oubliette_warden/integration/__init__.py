"""Integration adapters for substrate services (CALDERA, Qdrant, Ollama).

These modules expose the *contract* between Oubliette Warden agents and the
underlying substrate. Each integration ships with an in-memory fake so
unit tests can exercise the full agent loop without bringing the real
substrate up.
"""
