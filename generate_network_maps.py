"""
Sovereign Shield — Interactive Network Map Generator

Generates 4 interactive HTML network visualizations using Pyvis + NetworkX:
  1. Agent Architecture Map — multi-agent orchestration pipeline with tools
  2. AWS Data Flow Map — cross-border flows between regions and services
  3. Regulation Compliance Map — regulations mapped to allowed/prohibited AWS regions
  4. Full System Map — combined view of all components and relationships

Run:
    pip install pyvis networkx
    python generate_network_maps.py

Output:
    visualizations/1_agent_architecture.html
    visualizations/2_aws_data_flows.html
    visualizations/3_regulation_compliance.html
    visualizations/4_full_system_map.html
"""

from __future__ import annotations

import os

from pyvis.network import Network

OUTPUT_DIR = "visualizations"

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
COLORS = {
    "orchestrator": "#FF6B35",
    "agent": "#004E89",
    "tool": "#2EC4B6",
    "aws_service": "#FF9F1C",
    "region_eu": "#1A936F",
    "region_india": "#F18F01",
    "region_china": "#C73E1D",
    "region_brazil": "#3C91E6",
    "region_us": "#9B5DE5",
    "region_other": "#888888",
    "regulation_eu": "#1A936F",
    "regulation_india": "#F18F01",
    "regulation_china": "#C73E1D",
    "regulation_brazil": "#3C91E6",
    "flow_replication": "#E63946",
    "flow_edge_cache": "#F4A261",
    "flow_stream": "#2A9D8F",
    "flow_peering": "#9B5DE5",
    "severity_critical": "#DC2626",
    "severity_high": "#EA580C",
    "severity_medium": "#D97706",
    "severity_low": "#65A30D",
    "data_category": "#8B5CF6",
    "remediation": "#06B6D4",
    "report": "#EC4899",
}

# ---------------------------------------------------------------------------
# Region data
# ---------------------------------------------------------------------------
EU_REGIONS = {
    "eu-west-1": "Ireland",
    "eu-west-2": "London",
    "eu-west-3": "Paris",
    "eu-central-1": "Frankfurt",
    "eu-central-2": "Zurich",
    "eu-south-1": "Milan",
    "eu-south-2": "Spain",
    "eu-north-1": "Stockholm",
}
EU_ADEQUACY_EXTRA = {
    "ca-central-1": "Canada",
    "ap-northeast-1": "Tokyo",
    "il-central-1": "Israel",
}
INDIA_REGIONS = {"ap-south-1": "Mumbai", "ap-south-2": "Hyderabad"}
CHINA_REGIONS = {"cn-north-1": "Beijing", "cn-northwest-1": "Ningxia"}
BRAZIL_REGIONS = {"sa-east-1": "São Paulo"}
US_REGIONS = {"us-east-1": "N. Virginia", "us-west-2": "Oregon"}
OTHER_REGIONS = {"ap-southeast-1": "Singapore", "me-south-1": "Bahrain", "af-south-1": "Cape Town"}


def _region_color(code: str) -> str:
    if code in EU_REGIONS:
        return COLORS["region_eu"]
    if code in INDIA_REGIONS:
        return COLORS["region_india"]
    if code in CHINA_REGIONS:
        return COLORS["region_china"]
    if code in BRAZIL_REGIONS:
        return COLORS["region_brazil"]
    if code in US_REGIONS:
        return COLORS["region_us"]
    return COLORS["region_other"]


ALL_REGIONS = {**EU_REGIONS, **EU_ADEQUACY_EXTRA, **INDIA_REGIONS, **CHINA_REGIONS, **BRAZIL_REGIONS, **US_REGIONS, **OTHER_REGIONS}


# ===================================================================
# MAP 1: Agent Architecture
# ===================================================================
def build_agent_architecture() -> Network:
    net = Network(
        height="900px", width="100%", bgcolor="#0F172A", font_color="white",
        directed=True, notebook=False,
        heading="Sovereign Shield — Agent Architecture Map",
    )
    net.set_options("""
    {
      "physics": {
        "hierarchicalRepulsion": { "centralGravity": 0.3, "springLength": 250, "nodeDistance": 200 },
        "solver": "hierarchicalRepulsion"
      },
      "layout": { "hierarchical": { "enabled": true, "direction": "UD", "sortMethod": "directed", "levelSeparation": 180 } },
      "edges": { "smooth": { "type": "cubicBezier" }, "arrows": { "to": { "enabled": true, "scaleFactor": 1.2 } } }
    }
    """)

    # Orchestrator
    net.add_node("orchestrator", label="Orchestrator\nAgent", color=COLORS["orchestrator"],
                 size=55, shape="diamond", font={"size": 16, "color": "white"},
                 title="Main coordinator — calls specialists in sequence\nModel: Claude Sonnet 4 (Bedrock)")

    # Specialist agents
    agents = [
        ("jurisdiction_profiler", "1. Jurisdiction\nProfiler", "Analyzes applicable regulations\nbased on regions, data types, industry"),
        ("data_flow_scanner", "2. Data Flow\nScanner", "Discovers cross-border data\nmovements across 8 AWS services"),
        ("violation_detector", "3. Violation\nDetector", "Cross-refs flows against\nregulation constraints"),
        ("remediation_generator", "4. Remediation\nGenerator", "Produces fixes, SCPs,\narchitecture alternatives"),
        ("report_generator", "5. Report\nGenerator", "Synthesizes executive-ready\nSovereignty Posture Report"),
    ]
    for i, (aid, label, title) in enumerate(agents):
        net.add_node(aid, label=label, color=COLORS["agent"], size=40, shape="box",
                     font={"size": 14, "color": "white"}, title=title, level=1)
        net.add_edge("orchestrator", aid, color="#FFFFFF88", width=2,
                     title=f"Step {i+1}", label=f"  {i+1}")

    # Scanner tools (under data_flow_scanner)
    scanners = [
        ("scan_s3", "S3\nScanner", "scan_s3_buckets()\nReplication rules, SSE"),
        ("scan_rds", "RDS\nScanner", "scan_rds_instances()\nRead replicas, clusters"),
        ("scan_ddb", "DynamoDB\nScanner", "scan_dynamodb_tables()\nGlobal table replicas"),
        ("scan_cf", "CloudFront\nScanner", "scan_cloudfront_distributions()\nEdge caches, origins"),
        ("scan_kms", "KMS\nScanner", "scan_kms_keys()\nMulti-region keys"),
        ("scan_sns", "SNS/SQS\nScanner", "scan_sns_sqs()\nCross-region subscriptions"),
        ("scan_tgw", "Transit GW\nScanner", "scan_transit_gateways()\nCross-region peering"),
        ("scan_edge", "Lambda@Edge\nScanner", "scan_lambda_at_edge()\nEdge-executing functions"),
    ]
    for sid, label, title in scanners:
        net.add_node(sid, label=label, color=COLORS["tool"], size=25, shape="box",
                     font={"size": 11, "color": "white"}, title=title, level=2)
        net.add_edge("data_flow_scanner", sid, color="#2EC4B688", width=1.5)

    # Violation tool
    net.add_node("check_violations", label="check_violations()", color=COLORS["tool"], size=25, shape="box",
                 font={"size": 11, "color": "white"}, title="Cross-refs scan results\nagainst regulation constraints", level=2)
    net.add_edge("violation_detector", "check_violations", color="#2EC4B688", width=1.5)

    # Remediation tools
    for tid, label, title in [
        ("gen_plan", "generate_\nremediation_plan()", "Step-by-step fixes\nwith CLI commands"),
        ("gen_scp", "generate_\nscp_policy()", "Ready-to-deploy\nSCP JSON documents"),
    ]:
        net.add_node(tid, label=label, color=COLORS["tool"], size=25, shape="box",
                     font={"size": 11, "color": "white"}, title=title, level=2)
        net.add_edge("remediation_generator", tid, color="#2EC4B688", width=1.5)

    # Regulation KB (used by jurisdiction_profiler and violation_detector)
    net.add_node("reg_kb", label="Regulation\nKnowledge Base\n(7 regulations)", color=COLORS["data_category"],
                 size=30, shape="database", font={"size": 12, "color": "white"},
                 title="GDPR, EU Data Act, DPDP,\nPIPL, LGPD, DORA, NIS2", level=2)
    net.add_edge("jurisdiction_profiler", "reg_kb", color="#8B5CF688", width=1.5, dashes=True)
    net.add_edge("check_violations", "reg_kb", color="#8B5CF688", width=1.5, dashes=True)

    # Output
    net.add_node("report_output", label="Sovereignty\nPosture Report", color=COLORS["report"],
                 size=30, shape="star", font={"size": 12, "color": "white"},
                 title="Executive-ready Markdown report\nRisk scores, violation tables,\nremediation timeline", level=2)
    net.add_edge("report_generator", "report_output", color="#EC489988", width=2)

    return net


# ===================================================================
# MAP 2: AWS Data Flow Map (sample cross-border flows)
# ===================================================================
def build_data_flow_map() -> Network:
    net = Network(
        height="900px", width="100%", bgcolor="#0F172A", font_color="white",
        directed=True, notebook=False,
        heading="Sovereign Shield — AWS Cross-Border Data Flow Map",
    )
    net.set_options("""
    {
      "physics": { "forceAtlas2Based": { "gravitationalConstant": -80, "springLength": 200 }, "solver": "forceAtlas2Based", "stabilization": { "iterations": 200 } },
      "edges": { "smooth": { "type": "curvedCW", "roundness": 0.15 }, "arrows": { "to": { "enabled": true, "scaleFactor": 1.0 } } }
    }
    """)

    # Add region nodes
    scan_regions = {
        **{k: v for k, v in EU_REGIONS.items() if k in ("eu-west-1", "eu-central-1", "eu-west-2", "eu-north-1")},
        **INDIA_REGIONS, **CHINA_REGIONS, **BRAZIL_REGIONS, **US_REGIONS,
        "ap-southeast-1": "Singapore", "ap-northeast-1": "Tokyo",
    }
    for code, name in scan_regions.items():
        color = _region_color(code)
        net.add_node(code, label=f"{name}\n({code})", color=color, size=35, shape="dot",
                     font={"size": 13, "color": "white"}, title=f"AWS Region: {code}\nLocation: {name}")

    net.add_node("global-edge", label="Global Edge\nLocations", color=COLORS["region_other"],
                 size=30, shape="triangle", font={"size": 12, "color": "white"},
                 title="CloudFront / Lambda@Edge\nAll worldwide PoPs")

    # Sample data flows (representing typical violations)
    flows = [
        # S3 replication
        ("eu-central-1", "us-east-1", "S3 Replication\ncustomer-pii-prod", COLORS["flow_replication"], 3, "S3 bucket cross-region replication\nVIOLATES: GDPR Art. 44"),
        ("eu-central-1", "eu-west-1", "S3 Replication\neu-analytics", COLORS["region_eu"], 2, "S3 bucket replication within EU\nCOMPLIANT"),
        # RDS replicas
        ("eu-west-1", "ap-southeast-1", "RDS Read Replica\norders-primary", COLORS["flow_replication"], 3, "RDS cross-region read replica\nVIOLATES: GDPR Art. 44"),
        ("eu-west-1", "eu-central-1", "RDS Read Replica\neu-analytics-db", COLORS["region_eu"], 2, "RDS replica within EU\nCOMPLIANT"),
        # DynamoDB global table
        ("ap-south-1", "cn-north-1", "DynamoDB Global Table\nuser-sessions", COLORS["severity_critical"], 4, "DynamoDB replication India→China\nVIOLATES: DPDP (prohibited region)"),
        ("ap-south-1", "ap-south-2", "DynamoDB Global Table\nindia-users", COLORS["region_india"], 2, "DynamoDB replication within India\nCOMPLIANT"),
        # CloudFront
        ("eu-central-1", "global-edge", "CloudFront Edge Cache\nE1A2B3C4D5E6F7", COLORS["flow_edge_cache"], 2.5, "CloudFront distributes EU data globally\nVIOLATES: GDPR (global edge caching)"),
        # KMS multi-region
        ("eu-central-1", "us-west-2", "KMS Multi-Region Key", COLORS["flow_replication"], 2, "KMS key replicated outside EU\nVIOLATES: GDPR"),
        # SNS cross-region
        ("eu-west-1", "us-east-1", "SNS→SQS Cross-Region\nalert-topic", COLORS["flow_stream"], 2, "SNS topic delivers to SQS in US\nVIOLATES: GDPR Art. 44"),
        # Transit Gateway
        ("eu-central-1", "ap-south-1", "Transit GW Peering", COLORS["flow_peering"], 2, "Network peering EU↔India\nPotential data path outside EU"),
        # Brazil
        ("sa-east-1", "us-east-1", "S3 Replication\nbr-customer-data", COLORS["flow_replication"], 2.5, "S3 replication Brazil→US\nRequires LGPD adequacy check"),
        # China
        ("cn-north-1", "ap-southeast-1", "RDS Read Replica\nchina-orders", COLORS["severity_critical"], 3, "RDS replication China→Singapore\nVIOLATES: PIPL Art. 38"),
    ]

    for src, dst, label, color, width, title in flows:
        net.add_edge(src, dst, label=label, color=color, width=width, title=title,
                     font={"size": 10, "color": "#FFFFFFBB", "strokeWidth": 0, "align": "middle"})

    # Legend nodes (positioned aside)
    legend_items = [
        ("legend_compliant", "Compliant Flow", COLORS["region_eu"], "dot"),
        ("legend_violation", "Violation Flow", COLORS["flow_replication"], "dot"),
        ("legend_critical", "Critical Violation", COLORS["severity_critical"], "dot"),
        ("legend_edge", "Edge Cache Flow", COLORS["flow_edge_cache"], "dot"),
        ("legend_stream", "Stream/Message Flow", COLORS["flow_stream"], "dot"),
        ("legend_peering", "Network Peering", COLORS["flow_peering"], "dot"),
    ]
    for lid, label, color, shape in legend_items:
        net.add_node(lid, label=label, color=color, size=12, shape=shape,
                     font={"size": 10, "color": "white"}, physics=False, x=-600, y=-350 + legend_items.index((lid, label, color, shape)) * 40)

    return net


# ===================================================================
# MAP 3: Regulation Compliance Map
# ===================================================================
def build_regulation_map() -> Network:
    net = Network(
        height="900px", width="100%", bgcolor="#0F172A", font_color="white",
        directed=True, notebook=False,
        heading="Sovereign Shield — Regulation-to-Region Compliance Map",
    )
    net.set_options("""
    {
      "physics": { "forceAtlas2Based": { "gravitationalConstant": -120, "springLength": 250, "damping": 0.5 }, "solver": "forceAtlas2Based", "stabilization": { "iterations": 300 } },
      "edges": { "smooth": { "type": "curvedCW", "roundness": 0.1 }, "arrows": { "to": { "enabled": true, "scaleFactor": 0.8 } } }
    }
    """)

    # Regulation nodes
    regulations = [
        ("gdpr", "GDPR\n(EU)", COLORS["regulation_eu"], "Art. 44-49\nPersonal data, PII\nSensitive data"),
        ("eu-data-act", "EU Data Act", COLORS["regulation_eu"], "Art. 27, 31\nIoT data, industrial data"),
        ("dpdp", "DPDP\n(India)", COLORS["regulation_india"], "Sec. 16-17\nPersonal data\nCritical personal data"),
        ("pipl", "PIPL\n(China)", COLORS["regulation_china"], "Art. 38-40\nPersonal data, PII"),
        ("lgpd", "LGPD\n(Brazil)", COLORS["regulation_brazil"], "Art. 33-34\nPersonal data, PII"),
        ("dora", "DORA\n(EU Financial)", COLORS["regulation_eu"], "Art. 28, 31\nFinancial data\nTransaction data"),
        ("nis2", "NIS2\n(EU Cybersecurity)", COLORS["regulation_eu"], "Art. 21, 23\nCritical infrastructure data"),
    ]
    for rid, label, color, title in regulations:
        net.add_node(rid, label=label, color=color, size=45, shape="diamond",
                     font={"size": 14, "color": "white", "bold": True}, title=title)

    # Region nodes
    all_vis_regions = {
        **{k: v for k, v in EU_REGIONS.items() if k in ("eu-west-1", "eu-central-1", "eu-north-1", "eu-south-1")},
        **EU_ADEQUACY_EXTRA, **INDIA_REGIONS, **CHINA_REGIONS, **BRAZIL_REGIONS, **US_REGIONS,
        "ap-southeast-1": "Singapore",
    }
    for code, name in all_vis_regions.items():
        color = _region_color(code)
        net.add_node(code, label=f"{name}\n({code})", color=color, size=25, shape="dot",
                     font={"size": 11, "color": "white"})

    # GDPR → EU regions (allowed)
    for r in ["eu-west-1", "eu-central-1", "eu-north-1", "eu-south-1"]:
        net.add_edge("gdpr", r, color="#1A936F88", width=2, title="Allowed region",
                     label="  allowed", font={"size": 9, "color": "#1A936FAA"})
    for r in ["ca-central-1", "ap-northeast-1", "il-central-1"]:
        net.add_edge("gdpr", r, color="#1A936F44", width=1.5, dashes=True, title="Adequacy decision",
                     label="  adequacy", font={"size": 9, "color": "#1A936F88"})

    # EU Data Act → EU regions
    for r in ["eu-west-1", "eu-central-1"]:
        net.add_edge("eu-data-act", r, color="#1A936F88", width=1.5, title="Allowed region")

    # DPDP → India regions (allowed)
    for r in ["ap-south-1", "ap-south-2"]:
        net.add_edge("dpdp", r, color="#F18F0188", width=2, title="Allowed region")
    # DPDP → China (prohibited)
    for r in ["cn-north-1", "cn-northwest-1"]:
        net.add_edge("dpdp", r, color=COLORS["severity_critical"], width=3, title="PROHIBITED — explicit block",
                     label="  PROHIBITED", font={"size": 10, "color": "#DC2626"})

    # PIPL → China regions (allowed)
    for r in ["cn-north-1", "cn-northwest-1"]:
        net.add_edge("pipl", r, color="#C73E1D88", width=2, title="Allowed region (local storage only)")

    # LGPD → Brazil
    net.add_edge("lgpd", "sa-east-1", color="#3C91E688", width=2, title="Allowed region")
    for r in ["eu-central-1", "us-east-1", "ca-central-1"]:
        net.add_edge("lgpd", r, color="#3C91E644", width=1.5, dashes=True, title="Adequacy transfer allowed")

    # DORA → EU financial
    for r in ["eu-west-1", "eu-central-1"]:
        net.add_edge("dora", r, color="#1A936F88", width=2, title="Allowed region")

    # NIS2 → EU critical infra
    for r in ["eu-central-1", "eu-north-1"]:
        net.add_edge("nis2", r, color="#1A936F88", width=2, title="Allowed region")

    # Data categories as small nodes
    categories = [
        ("cat_pii", "Personal Data\n/ PII", ["gdpr", "dpdp", "pipl", "lgpd"]),
        ("cat_financial", "Financial\nData", ["dora"]),
        ("cat_critical_infra", "Critical Infra\nData", ["nis2"]),
        ("cat_iot", "IoT / Industrial\nData", ["eu-data-act"]),
        ("cat_sensitive", "Sensitive\nPersonal Data", ["gdpr"]),
        ("cat_critical_personal", "Critical Personal\nData (India)", ["dpdp"]),
    ]
    for cid, label, linked_regs in categories:
        net.add_node(cid, label=label, color=COLORS["data_category"], size=20, shape="box",
                     font={"size": 10, "color": "white"})
        for rid in linked_regs:
            net.add_edge(cid, rid, color="#8B5CF644", width=1, dashes=True, arrows="to")

    return net


# ===================================================================
# MAP 4: Full System Map
# ===================================================================
def build_full_system_map() -> Network:
    net = Network(
        height="1000px", width="100%", bgcolor="#0F172A", font_color="white",
        directed=True, notebook=False,
        heading="Sovereign Shield — Full System Architecture Map",
    )
    net.set_options("""
    {
      "physics": { "forceAtlas2Based": { "gravitationalConstant": -150, "springLength": 200, "damping": 0.6 }, "solver": "forceAtlas2Based", "stabilization": { "iterations": 400 } },
      "edges": { "smooth": { "type": "curvedCW", "roundness": 0.1 }, "arrows": { "to": { "enabled": true, "scaleFactor": 0.9 } } }
    }
    """)

    # --- Layer 1: Entry Points ---
    net.add_node("cli", label="CLI\n(sovereign-shield)", color="#94A3B8", size=30, shape="box",
                 font={"size": 12, "color": "white"}, title="Command-line interface\n--regions, --regulations, --interactive")
    net.add_node("lambda", label="Lambda\nHandler", color="#94A3B8", size=30, shape="box",
                 font={"size": 12, "color": "white"}, title="AWS Lambda entry point\naction: scan | chat")
    net.add_node("stepfn", label="Step\nFunctions", color="#94A3B8", size=25, shape="box",
                 font={"size": 11, "color": "white"}, title="Orchestrated pipeline\n15 min timeout")
    net.add_node("eventbridge", label="EventBridge\n(Daily 6AM)", color="#94A3B8", size=25, shape="box",
                 font={"size": 11, "color": "white"}, title="Scheduled daily scan")

    # --- Layer 2: Orchestrator ---
    net.add_node("orchestrator", label="Orchestrator\nAgent", color=COLORS["orchestrator"],
                 size=50, shape="diamond", font={"size": 15, "color": "white", "bold": True},
                 title="Central coordinator\nClaude Sonnet 4 (Bedrock)")

    net.add_edge("cli", "orchestrator", color="#94A3B888", width=2)
    net.add_edge("lambda", "orchestrator", color="#94A3B888", width=2)
    net.add_edge("stepfn", "lambda", color="#94A3B844", width=1.5)
    net.add_edge("eventbridge", "lambda", color="#94A3B844", width=1.5, dashes=True)

    # --- Layer 3: Specialist Agents ---
    agents = [
        ("jp", "1. Jurisdiction\nProfiler", COLORS["agent"]),
        ("dfs", "2. Data Flow\nScanner", COLORS["agent"]),
        ("vd", "3. Violation\nDetector", COLORS["agent"]),
        ("rg", "4. Remediation\nGenerator", COLORS["agent"]),
        ("rpg", "5. Report\nGenerator", COLORS["agent"]),
    ]
    for i, (aid, label, color) in enumerate(agents):
        net.add_node(aid, label=label, color=color, size=35, shape="box",
                     font={"size": 13, "color": "white"})
        net.add_edge("orchestrator", aid, color="#FFFFFF66", width=2, label=f"  {i+1}")

    # Pipeline sequence edges
    for a, b in [("jp", "dfs"), ("dfs", "vd"), ("vd", "rg"), ("rg", "rpg")]:
        net.add_edge(a, b, color="#FFFFFF22", width=1, dashes=True)

    # --- Layer 4: Tools ---
    scanner_tools = [
        ("t_s3", "S3"), ("t_rds", "RDS"), ("t_ddb", "DynamoDB"), ("t_cf", "CloudFront"),
        ("t_kms", "KMS"), ("t_sns", "SNS/SQS"), ("t_tgw", "Transit\nGateway"), ("t_edge", "Lambda\n@Edge"),
    ]
    for tid, label in scanner_tools:
        net.add_node(tid, label=label, color=COLORS["tool"], size=20, shape="box",
                     font={"size": 10, "color": "white"})
        net.add_edge("dfs", tid, color="#2EC4B644", width=1.5)

    net.add_node("t_check", label="check_\nviolations()", color=COLORS["tool"], size=20, shape="box",
                 font={"size": 10, "color": "white"})
    net.add_edge("vd", "t_check", color="#2EC4B644", width=1.5)

    net.add_node("t_plan", label="generate_\nplan()", color=COLORS["tool"], size=20, shape="box",
                 font={"size": 10, "color": "white"})
    net.add_node("t_scp", label="generate_\nscp()", color=COLORS["tool"], size=20, shape="box",
                 font={"size": 10, "color": "white"})
    net.add_edge("rg", "t_plan", color="#2EC4B644", width=1.5)
    net.add_edge("rg", "t_scp", color="#2EC4B644", width=1.5)

    # --- Layer 5: Regulation KB ---
    net.add_node("reg_kb", label="Regulation\nKnowledge Base", color=COLORS["data_category"],
                 size=30, shape="database", font={"size": 12, "color": "white"},
                 title="7 regulations:\nGDPR, EU Data Act, DPDP,\nPIPL, LGPD, DORA, NIS2")
    net.add_edge("jp", "reg_kb", color="#8B5CF644", width=1.5, dashes=True)
    net.add_edge("t_check", "reg_kb", color="#8B5CF644", width=1.5, dashes=True)

    regs = [
        ("r_gdpr", "GDPR", COLORS["regulation_eu"]),
        ("r_euda", "EU Data\nAct", COLORS["regulation_eu"]),
        ("r_dpdp", "DPDP", COLORS["regulation_india"]),
        ("r_pipl", "PIPL", COLORS["regulation_china"]),
        ("r_lgpd", "LGPD", COLORS["regulation_brazil"]),
        ("r_dora", "DORA", COLORS["regulation_eu"]),
        ("r_nis2", "NIS2", COLORS["regulation_eu"]),
    ]
    for rid, label, color in regs:
        net.add_node(rid, label=label, color=color, size=18, shape="dot",
                     font={"size": 10, "color": "white"})
        net.add_edge("reg_kb", rid, color=color + "44", width=1)

    # --- Layer 6: AWS Regions (sample) ---
    sample_regions = [
        ("eu-central-1", "Frankfurt"), ("eu-west-1", "Ireland"), ("us-east-1", "N. Virginia"),
        ("ap-south-1", "Mumbai"), ("cn-north-1", "Beijing"), ("sa-east-1", "São Paulo"),
    ]
    for code, name in sample_regions:
        color = _region_color(code)
        net.add_node(code, label=f"{name}\n({code})", color=color, size=22, shape="dot",
                     font={"size": 10, "color": "white"})

    for tid, _ in scanner_tools:
        for code, _ in sample_regions:
            net.add_edge(tid, code, color="#FFFFFF11", width=0.5)

    # --- Layer 7: Outputs ---
    net.add_node("report", label="Sovereignty\nPosture Report", color=COLORS["report"],
                 size=30, shape="star", font={"size": 13, "color": "white"},
                 title="Executive-ready Markdown\nRisk scores, violation tables,\nremediation timeline")
    net.add_edge("rpg", "report", color="#EC489988", width=2)

    net.add_node("scp_output", label="SCP Policy\nDocuments", color=COLORS["remediation"],
                 size=25, shape="star", font={"size": 11, "color": "white"},
                 title="Ready-to-deploy\nService Control Policies")
    net.add_edge("t_scp", "scp_output", color="#06B6D488", width=1.5)

    # --- Storage ---
    storage = [
        ("ddb_violations", "DynamoDB\nViolations", "#FF9F1C"),
        ("ddb_scans", "DynamoDB\nScan Results", "#FF9F1C"),
        ("s3_reports", "S3 Reports\nBucket", "#FF9F1C"),
    ]
    for sid, label, color in storage:
        net.add_node(sid, label=label, color=color, size=22, shape="database",
                     font={"size": 10, "color": "white"})

    net.add_edge("lambda", "ddb_violations", color="#FF9F1C44", width=1, dashes=True)
    net.add_edge("lambda", "ddb_scans", color="#FF9F1C44", width=1, dashes=True)
    net.add_edge("lambda", "s3_reports", color="#FF9F1C44", width=1, dashes=True)

    # Bedrock
    net.add_node("bedrock", label="Amazon\nBedrock\n(Claude Sonnet 4)", color="#FF6B35",
                 size=35, shape="hexagon", font={"size": 11, "color": "white"},
                 title="LLM provider for all agents")
    for aid, _, _ in agents:
        net.add_edge(aid, "bedrock", color="#FF6B3522", width=0.8, dashes=True)

    return net


# ===================================================================
# Main
# ===================================================================
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    maps = [
        ("1_agent_architecture", build_agent_architecture),
        ("2_aws_data_flows", build_data_flow_map),
        ("3_regulation_compliance", build_regulation_map),
        ("4_full_system_map", build_full_system_map),
    ]

    for name, builder in maps:
        print(f"Generating {name}...")
        net = builder()
        path = os.path.join(OUTPUT_DIR, f"{name}.html")
        net.save_graph(path)

        # Inject custom CSS for dark theme title
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            html = f.read()
        html = html.replace("<center>", '<center style="background:#0F172A; color:white; font-family:system-ui;">')
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  -> {path}")

    print(f"\nAll maps generated in {OUTPUT_DIR}/")
    print("Open any .html file in a browser to explore interactively.")
    print("  - Drag nodes to rearrange")
    print("  - Scroll to zoom")
    print("  - Hover over nodes/edges for details")


if __name__ == "__main__":
    main()
