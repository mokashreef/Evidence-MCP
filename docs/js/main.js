/**
 * Evidence MCP — Official Landing Page JavaScript
 * Bilingual Engine (English & Arabic), Interactive 24 Tools Catalog, Client Config Tabs,
 * and Mobile Drawer Navigation
 */

// 1. Tool Catalog Data (24 Tools)
const TOOLS_DATA = [
  {
    name: "create_evidence_bundle",
    category: "lifecycle",
    desc_en: "Initializes a new tamper-proof evidence bundle for a task or PR session.",
    desc_ar: "إنشاء حزمة أدلة مشفرة جديدة وغير قابلة للتلاعب لمهمة برمجية محددة.",
    inputs: "task, workspacePath, metadata?, additionalWorkspaces?",
    output: "bundleId, initial status ('in_progress')"
  },
  {
    name: "snapshot_files",
    category: "lifecycle",
    desc_en: "Computes live SHA-256 digests and file sizes strictly within workspace boundaries.",
    desc_ar: "حساب بصمات التجزئة SHA-256 وأحجام الملفات بدقة داخل حدود مساحة العمل.",
    inputs: "bundleId, paths: string[], workspaceName?",
    output: "snapshots: [{ evidenceId, workspaceName, path, sha256 }]"
  },
  {
    name: "add_assertion",
    category: "lifecycle",
    desc_en: "Attaches a verifiable engineering claim backed by at least one recorded evidence ID.",
    desc_ar: "إرفاق ادعاء هندسي معتمد وموثق مدعوم بمعرف دليل واحد على الأقل.",
    inputs: "bundleId, claim: string, evidenceIds: string[]",
    output: "assertionId, claim, evidenceIds"
  },
  {
    name: "sign_evidence_bundle",
    category: "lifecycle",
    desc_en: "Cryptographically signs the bundle canonical payload using native Ed25519.",
    desc_ar: "توقيع حزمة الأدلة تشفيرياً باستخدام خوارزمية Ed25519 دون أي اعتماديات خارجية.",
    inputs: "bundleId, agentId?, privateKeyPath?",
    output: "attestation: { agentId, algorithm, publicKey, signature }"
  },
  {
    name: "verify_evidence_bundle",
    category: "lifecycle",
    desc_en: "Validates file hashes, Git HEAD status, AST symbols, signatures, and registry state.",
    desc_ar: "التحقق المباشر من بصمات الملفات وحالة Git وشجرة AST والتوقيعات وسجل الوكلاء.",
    inputs: "bundleId, workspacePath?",
    output: "status ('verified' | 'stale' | 'failed'), items, reasons"
  },
  {
    name: "export_evidence_report",
    category: "lifecycle",
    desc_en: "Generates an offline-safe HTML, Markdown, JSON, or OASIS SARIF v2.1.0 audit report.",
    desc_ar: "تصدير تقرير تدقيق متكامل بصيغ HTML تفاعلية أو Markdown أو SARIF v2.1.0 لـ GitHub.",
    inputs: "bundleId, format ('html' | 'markdown' | 'json' | 'sarif'), policyPath?",
    output: "Formatted report string and export metadata"
  },
  {
    name: "execute_verified_command",
    category: "execution",
    desc_en: "Spawns approved commands in a sandboxed runner with active concurrency semaphores.",
    desc_ar: "تشغيل الأوامر المصرح بها في بيئة معزولة آمنة مع التحكم في التزامن وتطهير البيئة.",
    inputs: "bundleId, command, args?, cwd?, workspaceName?",
    output: "evidenceId, exitCode, durationMs, provenance: 'server_executed'"
  },
  {
    name: "record_command_result",
    category: "execution",
    desc_en: "Records an agent-reported execution result (provenance: 'agent_reported').",
    desc_ar: "تسجيل نتائج تنفيذ الأوامر المبلغة من قبل الوكيل مع تمييز مصدرها.",
    inputs: "bundleId, command, exitCode, stdout, stderr, workspaceName?",
    output: "evidenceId, command, exitCode, provenance"
  },
  {
    name: "register_workspace",
    category: "execution",
    desc_en: "Binds secondary monorepo packages or workspaces with strict path confinement.",
    desc_ar: "ربط حزم المستودعات المتعددة (Monorepo) بحزمة الأدلة مع فرض حدود العزل الصارمة.",
    inputs: "bundleId, name, path",
    output: "workspaceName, workspacePath, allWorkspaces"
  },
  {
    name: "capture_git_evidence",
    category: "ast",
    desc_en: "Captures Git HEAD commit, branch, working tree status, and unstaged modifications.",
    desc_ar: "التقاط رقم إيداع Git HEAD والفرع الحالي وحالة التعديلات غير المحفوظة في المستودع.",
    inputs: "bundleId, workspaceName?, workspacePath?",
    output: "evidenceId, branch, headCommit, isClean"
  },
  {
    name: "capture_ast_evidence",
    category: "ast",
    desc_en: "Extracts AST symbols and flags breaking changes across 8+ languages via modular plugins.",
    desc_ar: "استخراج رموز الشجرة النحوية وتحديد التغييرات الكاسرة عبر إضافات لغوية موديولار.",
    inputs: "bundleId, files: string[], workspaceName?, compareWithGitHead?",
    output: "astEvidence: [{ id, filePath, symbolsCount, isBreakingChange }]"
  },
  {
    name: "capture_sbom_evidence",
    category: "supplychain",
    desc_en: "Generates signed CycloneDX v1.5 SBOM across npm, Go, Rust, and Python manifests.",
    desc_ar: "توليد جرد برمجيات CycloneDX v1.5 موقّع لمشاريع npm و Go و Rust و Python.",
    inputs: "bundleId, workspaceName?, includeDevDependencies?, outputPath?",
    output: "evidenceId, componentCount, bomDigest, licenseSummary"
  },
  {
    name: "export_slsa_provenance",
    category: "supplychain",
    desc_en: "Generates and signs in-toto v1 Statement / SLSA Provenance v1.0 attestations.",
    desc_ar: "توليد وتوقيع إثباتات المنشأ القياسية SLSA Provenance v1.0 / in-toto v1.",
    inputs: "bundleId, builderId?, sign?: boolean, outputPath?",
    output: "statementDigest, subjectCount, dependencyCount, provenance"
  },
  {
    name: "notarize_evidence_bundle",
    category: "transparency",
    desc_en: "Anchors anonymized bundle SHA-256 digest to remote transparency logs via SSRF-safe HTTP.",
    desc_ar: "تثبيت بصمة الحزمة المجهولة في سجلات الشفافية عن بعد بأمان شبكي تام ضد هجمات SSRF.",
    inputs: "bundleId, notaryUrl, authToken?, allowPrivateNetwork?",
    output: "receiptId, logIndex, merkleLeafHash, notaryKeyFingerprint"
  },
  {
    name: "submit_rekor_entry",
    category: "transparency",
    desc_en: "Submits attestation to Sigstore Rekor and audits RFC 6962 Merkle tree inclusion proofs.",
    desc_ar: "إرسال التوقيع إلى سجل Sigstore Rekor والتحقق من براهين شجرة ميركل RFC 6962 دون اتصال.",
    inputs: "bundleId, rekorUrl?, privateKeyPem?, allowPrivateNetwork?",
    output: "entryUuid, logIndex, inclusionProof, verified: boolean"
  },
  {
    name: "endorse_evidence_bundle",
    category: "consensus",
    desc_en: "Cryptographically signs a multi-agent peer endorsement or veto with an engineering role.",
    desc_ar: "توقيع مراجعة النظراء بين الوكلاء المتعددين تشفيرياً مع تحديد الدور الهندسي والقرار.",
    inputs: "bundleId, agentId, role, verdict, comment, privateKeyPem?",
    output: "endorsementId, verdict, signature, totalEndorsements"
  },
  {
    name: "check_bundle_quorum",
    category: "consensus",
    desc_en: "Evaluates peer endorsements against threshold quorum, required roles, and registry status.",
    desc_ar: "فحص اكتمال النصاب القانوني لمراجعات الوكلاء والتحقق من الأدوار المطلوبة وسجل الثقة.",
    inputs: "bundleId, minEndorsements?, requiredRoles?, requireTrustedRegistry?",
    output: "satisfied: boolean, approvedCount, rejectionsCount, reasons"
  },
  {
    name: "export_verification_proof",
    category: "proofs",
    desc_en: "Issues an Ed25519 cryptographically signed standalone portable verification proof.",
    desc_ar: "إصدار برهان تحقق محمول وموقع تشفيرياً بـ Ed25519 يمكن مشاركته وتدقيقه مستقلاً.",
    inputs: "bundleId, privateKeyPem?, workspacePath?",
    output: "proofId, verdict, bundleDigest, signature"
  },
  {
    name: "verify_replay_proof",
    category: "proofs",
    desc_en: "Verifies signature authenticity and bundle digest consistency of an exported proof.",
    desc_ar: "التحقق من صحة توقيع البرهان ومطابقة بصمة الحزمة المسجلة دون تعديل.",
    inputs: "proofId?, proofJson?, bundleId?",
    output: "valid: boolean, verdict, bundleDigestMatches"
  },
  {
    name: "evaluate_evidence_policy",
    category: "policy",
    desc_en: "Evaluates bundle compliance against declarative rules in evidence.policy.json.",
    desc_ar: "تدقيق الامتثال الآلي لحزمة الأدلة وفق القواعد المعلنة في evidence.policy.json.",
    inputs: "bundleId, policyPath?, policy?, strict?: boolean, workspacePath?",
    output: "passed: boolean, summary, rulesEvaluated, evaluations"
  },
  {
    name: "dispatch_webhook_audit",
    category: "policy",
    desc_en: "Dispatches HMAC-SHA256 authenticated audit payloads to remote webhook endpoints.",
    desc_ar: "إرسال حمولة تدقيق موثقة بتوقيع HMAC-SHA256 إلى نقاط نهاية Webhook مع إعادة المحاولة.",
    inputs: "bundleId, webhookUrl, secretToken?, includeProof?, timeoutMs?",
    output: "delivered: boolean, statusCode, signatureHeader, durationMs"
  },
  {
    name: "register_trusted_agent",
    category: "registry",
    desc_en: "Registers an authorized agent public key and assigned role into workspace registry.",
    desc_ar: "تسجيل المفتاح العام للوكيل المصرح له وتعيين دوره في سجل الهويات المعتمدة.",
    inputs: "agentId, name, role, publicKeyPem, expiresAt?, metadata?",
    output: "agentId, name, role, keyFingerprint, status: 'active'"
  },
  {
    name: "revoke_trusted_agent",
    category: "registry",
    desc_en: "Revokes a trusted agent key in the workspace registry with an immutable reason.",
    desc_ar: "إلغاء وتجميد مفتاح وكيل في السجل مع توثيق سبب الإلغاء بشكل دائم.",
    inputs: "agentId, reason: string, workspacePath?",
    output: "agentId, status: 'revoked', revokedAt, revocationReason"
  },
  {
    name: "generate_client_config",
    category: "registry",
    desc_en: "Generates and merges MCP configuration for Claude, Cursor, Gemini, or Cline.",
    desc_ar: "توليد ودمج إعدادات تشغيل خادم MCP تلقائياً لعملاء Cursor و Claude و Gemini و Cline.",
    inputs: "client ('claude' | 'cursor' | 'gemini' | 'vscode-cline'), write?, workspace?",
    output: "client, configPath, snippet, written: boolean"
  }
];

// 2. Client Config Snippets Data
const CLIENT_CONFIGS = {
  cursor: {
    name: "Cursor",
    path_win: "%APPDATA%\\Cursor\\User\\globalStorage\\mcp.json (or .cursor/mcp.json)",
    path_unix: "~/.cursor/mcp.json",
    cli_cmd: "evidence-mcp client config cursor --write",
    snippet: `{
  "mcpServers": {
    "evidence": {
      "command": "node",
      "args": ["/path/to/Evidence-MCP/dist/cli.js", "--workspace", "."]
    }
  }
}`
  },
  claude: {
    name: "Claude Desktop",
    path_win: "%APPDATA%\\Claude\\claude_desktop_config.json",
    path_unix: "~/Library/Application Support/Claude/claude_desktop_config.json",
    cli_cmd: "evidence-mcp client config claude --write",
    snippet: `{
  "mcpServers": {
    "evidence": {
      "command": "node",
      "args": ["/path/to/Evidence-MCP/dist/cli.js", "--workspace", "."]
    }
  }
}`
  },
  gemini: {
    name: "Gemini Code Assist",
    path_win: "%APPDATA%\\Code\\User\\globalStorage\\gemini.mcp.json",
    path_unix: "~/.config/gemini/mcp.json",
    cli_cmd: "evidence-mcp client config gemini --write",
    snippet: `{
  "mcpServers": {
    "evidence": {
      "command": "node",
      "args": ["/path/to/Evidence-MCP/dist/cli.js", "--workspace", "."]
    }
  }
}`
  },
  cline: {
    name: "VS Code Cline",
    path_win: "%APPDATA%\\Code\\User\\globalStorage\\saoudrizwan.claude-dev\\settings\\cline_mcp_settings.json",
    path_unix: "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    cli_cmd: "evidence-mcp client config vscode-cline --write",
    snippet: `{
  "mcpServers": {
    "evidence": {
      "command": "node",
      "args": ["/path/to/Evidence-MCP/dist/cli.js", "--workspace", "."]
    }
  }
}`
  }
};

// 3. Bilingual Dictionary (Completely Emoji-Free)
const I18N = {
  en: {
    site_title: "Evidence MCP — Cryptographic Proof of Work for AI Coding Agents",
    nav_features: "Features",
    nav_architecture: "Architecture",
    nav_tools: "24 Tools",
    nav_clients: "Client Setup",
    nav_quickstart: "Quickstart",
    badge_hero: "Open Protocol for Verifiable AI Coding Agents",
    hero_title: 'Don\'t Just Trust AI Agents. <span class="gradient-text">Cryptographically Verify Them.</span>',
    hero_desc: "Evidence MCP is the zero-dependency Model Context Protocol server that captures tamper-proof engineering evidence: Ed25519 attestations, AST semantic diffs, CycloneDX SBOMs, SLSA v1.0 provenance, and Sigstore Rekor transparency logs.",
    btn_quickstart: "Quickstart Guide",
    btn_github: "View on GitHub",
    btn_config_gen: "Client Config Setup",
    stat_tools: "MCP Tools",
    stat_tools_sub: "Comprehensive suite",
    stat_deps: "Zero Dependencies",
    stat_deps_sub: "100% native Node.js crypto",
    stat_tests: "Passing Tests",
    stat_tests_sub: "100% green coverage",
    stat_clients: "AI Clients",
    stat_clients_sub: "Cursor, Claude, Gemini, Cline",
    sec_problem_sub: "The AI Integrity Gap",
    sec_problem_title: "Why Evidence-Based Verification Matters",
    sec_problem_desc: "AI coding agents are powerful but prone to hallucinating test passes, skipping commits, or leaving security regressions undetected.",
    comp_bad_title: "Traditional Coding Agents",
    comp_bad_1: "Hallucinates test passes without running real test commands",
    comp_bad_2: "Claims tasks are completed while leaving uncommitted changes",
    comp_bad_3: "Introduces silent breaking API changes across codebase",
    comp_bad_4: "No supply-chain inventory (SBOM) or tamper verification",
    comp_bad_5: "Single point of failure: 'Trust me, I fixed it'",
    comp_good_title: "With Evidence MCP",
    comp_good_1: "Sandboxed command runner verifies real exit codes & captured logs",
    comp_good_2: "Captures Git HEAD commit hash, branch, and working-tree cleanliness",
    comp_good_3: "AST semantic diff flags breaking changes across 8+ languages",
    comp_good_4: "Signs CycloneDX v1.5 SBOM & in-toto SLSA v1.0 provenance",
    comp_good_5: "Distributed Ed25519 multi-agent consensus quorum & Rekor logs",
    sec_arch_sub: "Core Architecture",
    sec_arch_title: "Built on 8 Pillars of Cryptographic Trust",
    sec_arch_desc: "Every claim made by an AI coding agent is anchored into verifiable mathematical and runtime proofs.",
    arch_1_title: "Ed25519 Attestations",
    arch_1_desc: "Asymmetric cryptographic signing using native Node.js crypto with deterministic canonical JSON serialization.",
    arch_2_title: "Sigstore Rekor Log",
    arch_2_desc: "Public and private transparency logs with offline RFC 6962 Merkle tree inclusion proof verification.",
    arch_3_title: "Multi-Ecosystem SBOM",
    arch_3_desc: "CycloneDX v1.5 dependency tracking across npm, Go, Rust, and Python with live manifest hash verification.",
    arch_4_title: "SLSA v1.0 Provenance",
    arch_4_desc: "Standardized in-toto Statement v1 linking artifacts, Git commits, SBOM dependencies, and build commands.",
    arch_5_title: "Modular AST Plugins",
    arch_5_desc: "Pluggable structural language parsers detecting breaking API modifications with custom grammar support.",
    arch_6_title: "Sandboxed Runner",
    arch_6_desc: "SSRF-protected execution runner with active concurrency semaphores and environment variable scrubbing.",
    arch_7_title: "Multi-Agent Consensus",
    arch_7_desc: "Cryptographic peer reviews (tester, auditor, architect) with threshold quorum voting and veto rights.",
    arch_8_title: "Declarative Policies",
    arch_8_desc: "Automated compliance checks via evidence.policy.json exporting SARIF v2.1.0 for GitHub Code Scanning.",
    sec_pipeline_sub: "Verification Lifecycle",
    sec_pipeline_title: "End-to-End Cryptographic Trust Pipeline",
    pipe_1: "1. Create Bundle",
    pipe_2: "2. Sandboxed Exec",
    pipe_3: "3. AST Diffing",
    pipe_4: "4. SBOM & SLSA",
    pipe_5: "5. Ed25519 Sign",
    pipe_6: "6. Rekor Audit",
    pipe_7: "7. Quorum Verdict",
    sec_tools_sub: "MCP Capabilities",
    sec_tools_title: "Explore the 24 Evidence MCP Tools",
    sec_tools_desc: "A rich catalog of standardized tools available to any MCP-compliant AI coding agent.",
    search_placeholder: "Search tools by name, description, or input...",
    chip_all: "All (24)",
    chip_lifecycle: "Lifecycle (6)",
    chip_execution: "Execution (3)",
    chip_ast: "AST & Git (2)",
    chip_supplychain: "Supply Chain (2)",
    chip_transparency: "Transparency (2)",
    chip_consensus: "Consensus (2)",
    chip_proofs: "Proofs & Replay (2)",
    chip_policy: "Policies (2)",
    chip_registry: "Registry & Clients (3)",
    sec_clients_sub: "Instant Integration",
    sec_clients_title: "One-Click Setup for Your Favorite AI Client",
    sec_clients_desc: "Configure Cursor, Claude Desktop, Gemini Code Assist, or VS Code Cline in seconds with automated CLI merging.",
    client_cli_label: "One-line automated configuration:",
    client_manual_label: "Or manually merge into config file:",
    sec_quick_sub: "Get Started in 3 Steps",
    sec_quick_title: "Integrate Evidence MCP Today",
    step_1_title: "1. Install and Bootstrap",
    step_1_desc: "Bootstrap recommended policies and .gitignore in your project with one command:",
    step_2_title: "2. Connect Your AI Agent",
    step_2_desc: "Automatically configure your preferred coding agent (e.g. Cursor):",
    step_3_title: "3. Enforce in GitHub Actions CI",
    step_3_desc: "Add the official composite action to verify evidence on every pull request:",
    footer_tagline: "The open standard for verifiable AI agent engineering. Built with zero dependencies on pure Node.js crypto.",
    footer_col_docs: "Documentation",
    footer_col_community: "Community & Code",
    footer_col_standards: "Standards",
    footer_copy: "© 2026 Evidence MCP. Released under the MIT License.",
    copy_btn: "Copy",
    copied_btn: "Copied!",
    nav_home: "Home"
  },
  ar: {
    site_title: "Evidence MCP — بروتوكول الأدلة المشفرة للوكلاء الذكية البرمجية",
    nav_features: "الميزات",
    nav_architecture: "المعمارية",
    nav_tools: "الـ 24 أداة",
    nav_clients: "إعداد العملاء",
    nav_quickstart: "البدء السريع",
    badge_hero: "بروتوكول مفتوح وموثوق لوكلاء البرمجة الذكية",
    hero_title: 'لا تكتفِ بالثقة بالوكيل الذكي. <span class="gradient-text">تحقق منه تشفيرياً برهانياً.</span>',
    hero_desc: "بروتوكول Evidence MCP هو خادم MCP مفتوح وخالٍ تماماً من الاعتماديات الخارجية، يلتقط حزم أدلة هندسية غير قابلة للتلاعب: توقيعات Ed25519، وفروقات AST النحوية، وجرد برمجيات CycloneDX، وإثباتات SLSA v1.0، وسجلات شفافية Rekor.",
    btn_quickstart: "دليل البدء السريع",
    btn_github: "المستودع على GitHub",
    btn_config_gen: "توليد إعدادات العميل",
    stat_tools: "أداة MCP متكاملة",
    stat_tools_sub: "شاملة لكل دورة التطوير",
    stat_deps: "صفر اعتماديات خارجية",
    stat_deps_sub: "100% تشفير Node.js أصلي",
    stat_tests: "اختبار معتمد بنجاح",
    stat_tests_sub: "تغطية كاملة بنسبة 100%",
    stat_clients: "عملاء ذكاء اصطناعي مدعومون",
    stat_clients_sub: "Cursor، Claude، Gemini، Cline",
    sec_problem_sub: "فجوة الثقة في البرمجة الذكية",
    sec_problem_title: "لماذا نحتاج للتحقق المشفر القاطع؟",
    sec_problem_desc: "الوكلاء البرمجية خارقة الذكاء، لكنها كثيراً ما تهلوس بنجاح الاختبارات أو تترك تغييرات غير محفوظة أو تُحدث تراجعات أمنية صامتة.",
    comp_bad_title: "الوكلاء التقليديون بدون أدلة",
    comp_bad_1: "يهلوس بنجاح الفحوصات دون تشغيل أمر الفحص فعلياً",
    comp_bad_2: "يدّعي إنجاز المهمة بينما الكود غير محفوظ في Git",
    comp_bad_3: "يُحدث تغييرات كاسرة في واجهات البرمجة دون تنبيهك",
    comp_bad_4: "غياب جرد التبعيات والبرمجيات الخبيثة (لا يوجد SBOM)",
    comp_bad_5: "نقطة فشل أحادية تعتمد على: 'ثق بي، لقد أصلحتها'",
    comp_good_title: "مع بروتوكول Evidence MCP",
    comp_good_1: "مشغّل معزول يسجل كود الخروج الفعلي وسجلات المخرجات بدقة",
    comp_good_2: "يوثق رقم إيداع Git HEAD والفرع ونظافة شجرة العمل",
    comp_good_3: "محلل AST يكتشف أي تغيير كاسر عبر أكثر من 8 لغات",
    comp_good_4: "يوقّع تشفيرياً جرد CycloneDX SBOM وإثباتات المنشأ SLSA v1.0",
    comp_good_5: "إجماع موزع وتصويت تشفيري بين وكلاء متعددين مع سجلات Rekor",
    sec_arch_sub: "المعمارية الأساسية",
    sec_arch_title: "مبني على 8 ركائز هندسية متينة",
    sec_arch_desc: "كل ادعاء يصدره الوكيل البرمجي يتم تثبيته ببراهين رياضية قاطعة لا تقبل التزوير.",
    arch_1_title: "توقيعات Ed25519 المشفرة",
    arch_1_desc: "توقيع تشفيري لا متماثل مبني كلياً على محرك Node.js مع تسلسل معياري محكم للبيانات لمنع أي تلاعب.",
    arch_2_title: "سجلات الشفافية Sigstore Rekor",
    arch_2_desc: "تثبيت الأدلة في سجلات الشفافية العامة والخاصة مع التحقق المباشر من براهين شجرة ميركل RFC 6962 دون اتصال.",
    arch_3_title: "جرد برمجيات متعدد المنظومات",
    arch_3_desc: "توليد ملفات CycloneDX v1.5 لمشاريع npm و Go و Rust و Python مع التحقق المباشر من مطابقة التجزئة للملفات.",
    arch_4_title: "إثباتات المنشأ SLSA v1.0",
    arch_4_desc: "توليد وتوقيع إثباتات in-toto Statement v1 تربط المخرجات بإيداعات Git والتبعيات والأوامر المنفذة بدقة.",
    arch_5_title: "إضافات AST النحوية الموديولار",
    arch_5_desc: "محللات نحوية معمارية تدعم اللغات الأساسية وقابلة للتوسع لأي لغة برمجية لكشف التغييرات الكاسرة في الدوال والفئات.",
    arch_6_title: "مشغل معزول وحماية SSRF",
    arch_6_desc: "تشغيل آمن للأوامر مع حظر عناوين الشبكات الداخلية وحجب المتغيرات الحساسة والتحكم في تزامن المعالجات.",
    arch_7_title: "إجماع الوكلاء المتعددين (Quorum)",
    arch_7_desc: "مراجعة تشفيرية بين وكلاء الفحص والأمان والمعمارية مع حق الفيتو وتحديد حد أدنى للموافقة (Quorum).",
    arch_8_title: "سياسات معلنة وتوافق SARIF",
    arch_8_desc: "تدقيق آلي صارم للسياسات عبر evidence.policy.json وتصدير النتائج مباشرة لـ GitHub Code Scanning عبر SARIF.",
    sec_pipeline_sub: "دورة التحقق التشفيري",
    sec_pipeline_title: "خط أنابيب الثقة والتحقق المتكامل",
    pipe_1: "1. إنشاء الحزمة",
    pipe_2: "2. تشغيل معزول",
    pipe_3: "3. فروقات AST",
    pipe_4: "4. جرد SBOM و SLSA",
    pipe_5: "5. توقيع Ed25519",
    pipe_6: "6. تدقيق Rekor",
    pipe_7: "7. إجماع النصاب",
    sec_tools_sub: "قدرات بروتوكول MCP",
    sec_tools_title: "استكشف قائمة الـ 24 أداة",
    sec_tools_desc: "كتالوج متكامل من الأدوات القياسية المتاحة لأي وكيل ذكاء اصطناعي يدعم بروتوكول MCP.",
    search_placeholder: "ابحث عن أداة بالاسم أو الشرح أو المدخلات...",
    chip_all: "الكل (24)",
    chip_lifecycle: "دورة الحياة (6)",
    chip_execution: "التنفيذ والعزل (3)",
    chip_ast: "التحليل النحوي و Git (2)",
    chip_supplychain: "سلسلة التوريد (2)",
    chip_transparency: "الشفافية و Rekor (2)",
    chip_consensus: "إجماع الوكلاء (2)",
    chip_proofs: "البراهين والإعادة (2)",
    chip_policy: "السياسات (2)",
    chip_registry: "السجل والعملاء (3)",
    sec_clients_sub: "تكامل فوري بنقرة واحدة",
    sec_clients_title: "إعداد سلس لأشهر عملاء البرمجة الذكية",
    sec_clients_desc: "قم بربط Evidence MCP مع Cursor أو Claude Desktop أو Gemini أو Cline في ثوانٍ مع الدمج التلقائي عبر الـ CLI.",
    client_cli_label: "أمر التهيئة التلقائي بسطر واحد:",
    client_manual_label: "أو الدمج اليدوي في ملف التكوين:",
    sec_quick_sub: "ابدأ في 3 خطوات بسيطة",
    sec_quick_title: "فعّل التحقق التشفيري في مشروعك اليوم",
    step_1_title: "1. التثبيت والتهيئة الأولية",
    step_1_desc: "قم بتوليد السياسات الموصى بها وملف .gitignore في مشروعك بأمر واحد:",
    step_2_title: "2. ربط وكيلك المفضل عبر MCP",
    step_2_desc: "قم بتهيئة عميل الذكاء الاصطناعي (مثل Cursor) تلقائياً:",
    step_3_title: "3. فرض التحقق في GitHub Actions CI",
    step_3_desc: "أضف إجراء GitHub Actions الرسمي للتحقق من الأدلة المشفرة في كل Pull Request:",
    footer_tagline: "المعيار المفتوح لتوثيق أعمال الوكلاء البرمجية تشفيرياً. مبني بدون أي اعتماديات خارجية وباعتماد كلي على Node.js.",
    footer_col_docs: "التوثيق",
    footer_col_community: "المجتمع والمستودع",
    footer_col_standards: "المعايير",
    footer_copy: "© 2026 Evidence MCP. مرخص بموجب رخصة MIT.",
    copy_btn: "نسخ",
    copied_btn: "تم النسخ!",
    nav_home: "الرئيسية"
  }
};

// 4. Current State
let currentLang = localStorage.getItem('evidence_lang') || 'en';
let currentCategory = 'all';
let currentSearch = '';
let currentClient = 'cursor';

// 5. DOM Elements & Initializer
document.addEventListener('DOMContentLoaded', () => {
  setupLanguageToggle();
  setupToolsFilter();
  setupClientTabs();
  setupCopyButtons();
  setupMobileDrawer();
  setupMobileBottomNav();
  applyLanguage(currentLang);
  renderTools();
  renderClientTab(currentClient);
});

// Apply Language
function applyLanguage(lang) {
  currentLang = lang;
  localStorage.setItem('evidence_lang', lang);
  
  const isRtl = lang === 'ar';
  document.documentElement.lang = lang;
  document.documentElement.dir = isRtl ? 'rtl' : 'ltr';
  
  const dict = I18N[lang];
  document.title = dict.site_title;
  
  // Update data-i18n text
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (dict[key]) {
      el.innerHTML = dict[key];
    }
  });

  // Update placeholders
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (dict[key]) {
      el.setAttribute('placeholder', dict[key]);
    }
  });

  // Update Lang toggle button (Pure SVG + text, ZERO emojis)
  const langText = isRtl ? 'English' : 'العربية';
  const globeSvg = `<svg class="lang-globe-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`;
  
  document.querySelectorAll('.lang-toggle').forEach(btn => {
    btn.innerHTML = `${globeSvg}<span>${langText}</span>`;
  });

  // Re-render dynamic components
  renderTools();
  renderClientTab(currentClient);
}

// Setup Language Toggle
function setupLanguageToggle() {
  document.querySelectorAll('.lang-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
      const newLang = currentLang === 'en' ? 'ar' : 'en';
      applyLanguage(newLang);
    });
  });
}

// Setup Mobile Navigation Drawer
function setupMobileDrawer() {
  const toggleBtn = document.getElementById('mobile-menu-toggle');
  const closeBtn = document.getElementById('mobile-drawer-close');
  const drawer = document.getElementById('mobile-nav-drawer');
  const backdrop = document.getElementById('mobile-nav-backdrop');

  if (!drawer || !backdrop) return;

  function openDrawer() {
    drawer.classList.add('open');
    backdrop.classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  function closeDrawer() {
    drawer.classList.remove('open');
    backdrop.classList.remove('open');
    document.body.style.overflow = '';
  }

  if (toggleBtn) toggleBtn.addEventListener('click', openDrawer);
  if (closeBtn) closeBtn.addEventListener('click', closeDrawer);
  if (backdrop) backdrop.addEventListener('click', closeDrawer);

  // Close drawer when clicking any link inside it
  drawer.querySelectorAll('.drawer-link').forEach(link => {
    link.addEventListener('click', closeDrawer);
  });
}

// Setup Mobile Bottom Navigation Highlight
function setupMobileBottomNav() {
  const bottomItems = document.querySelectorAll('.bottom-bar-item');
  bottomItems.forEach(item => {
    item.addEventListener('click', () => {
      bottomItems.forEach(i => i.classList.remove('active'));
      item.classList.add('active');
    });
  });
}

// Setup Tools Filtering & Search
function setupToolsFilter() {
  const searchInput = document.getElementById('tools-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      currentSearch = e.target.value.toLowerCase().trim();
      renderTools();
    });
  }

  const chips = document.querySelectorAll('.chip');
  chips.forEach(chip => {
    chip.addEventListener('click', () => {
      chips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      currentCategory = chip.getAttribute('data-category');
      renderTools();
    });
  });
}

// Render Tools Grid
function renderTools() {
  const container = document.getElementById('tools-grid');
  if (!container) return;
  
  const isAr = currentLang === 'ar';
  
  const filtered = TOOLS_DATA.filter(tool => {
    const matchCategory = currentCategory === 'all' || tool.category === currentCategory;
    const desc = isAr ? tool.desc_ar : tool.desc_en;
    const matchSearch = !currentSearch || 
      tool.name.toLowerCase().includes(currentSearch) ||
      desc.toLowerCase().includes(currentSearch) ||
      tool.inputs.toLowerCase().includes(currentSearch);
    return matchCategory && matchSearch;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 3rem; color: var(--text-muted);">
        ${isAr ? 'لم يتم العثور على أدوات تطابق البحث' : 'No tools matched your search query'}
      </div>
    `;
    return;
  }

  container.innerHTML = filtered.map(t => `
    <div class="tool-card">
      <div class="tool-header">
        <span class="tool-name">${t.name}</span>
        <span class="tool-cat">${t.category}</span>
      </div>
      <p class="tool-desc">${isAr ? t.desc_ar : t.desc_en}</p>
      <div class="tool-io">
        <div><strong style="color:var(--accent-cyan);">${isAr ? 'المدخلات' : 'Inputs'}:</strong> ${t.inputs}</div>
        <div style="margin-top:0.35rem;"><strong style="color:var(--accent-emerald);">${isAr ? 'المخرجات' : 'Output'}:</strong> ${t.output}</div>
      </div>
    </div>
  `).join('');
}

// Setup Client Tabs
function setupClientTabs() {
  const tabBtns = document.querySelectorAll('.client-tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentClient = btn.getAttribute('data-client');
      renderClientTab(currentClient);
    });
  });
}

// Render Client Tab Content
function renderClientTab(clientKey) {
  const data = CLIENT_CONFIGS[clientKey];
  if (!data) return;

  const cliCodeEl = document.getElementById('client-cli-code');
  const jsonCodeEl = document.getElementById('client-json-code');
  const pathWinEl = document.getElementById('client-path-win');
  const pathUnixEl = document.getElementById('client-path-unix');

  if (cliCodeEl) cliCodeEl.textContent = data.cli_cmd;
  if (jsonCodeEl) jsonCodeEl.textContent = data.snippet;
  if (pathWinEl) pathWinEl.textContent = data.path_win;
  if (pathUnixEl) pathUnixEl.textContent = data.path_unix;
}

// Setup Copy Buttons
function setupCopyButtons() {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.copy-btn');
    if (btn) {
      const targetId = btn.getAttribute('data-target');
      const targetEl = document.getElementById(targetId);
      if (targetEl) {
        const text = targetEl.textContent || targetEl.innerText;
        navigator.clipboard.writeText(text).then(() => {
          const dict = I18N[currentLang];
          const originalText = btn.textContent;
          btn.textContent = dict.copied_btn;
          btn.style.background = 'rgba(16, 185, 129, 0.3)';
          btn.style.color = 'var(--accent-emerald)';
          setTimeout(() => {
            btn.textContent = dict.copy_btn;
            btn.style.background = '';
            btn.style.color = '';
          }, 2000);
        });
      }
    }
  });
}
