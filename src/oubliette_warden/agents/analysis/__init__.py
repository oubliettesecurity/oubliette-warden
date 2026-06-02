"""Cyber Analysis agent — ingests scanner output, ranks findings transparently.

Public surface kept minimal; importers should reach for ``analyst.CyberAnalyst``,
``models.AnalyzedFinding``, and ``ranker.score`` directly.
"""
