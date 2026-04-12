# 📘 Network Forensics Ingestion & Preprocessing Layer

## Overview
This system implements a complete ingestion and preprocessing pipeline for PCAP-based forensic analysis.

Raw PCAP → Structured Evidence → AI Bundles → Retrieval Interface

## Architecture
Raw PCAP Files
↓
Evidence Registry
↓
Metadata Extraction
↓
Overlap Detection
↓
Chunking & Task Planning
↓
Extraction Executor
↓
AI Handoff Bundles
↓
Pre-AI Summaries
↓
Agent Interface API

## Outputs
- ai_handoff_bundles/
- preai_summaries/
- preai_retrieval/
- evidence_registry.db

## Usage Rules
DO NOT:
- parse PCAPs directly
- query DB manually

DO:
- use agent_interface.py

## Agent Workflow
1. list-bundles
2. get-summary
3. search
4. get-events
5. get-pcaps

## Summary
This layer provides structured, correlated, AI-ready evidence.
