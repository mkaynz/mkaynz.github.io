<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>McKenzie Holliday — Solutions Engineer</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,300;0,400;0,500;1,300&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet" />
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg: #0a0a0c;
  --bg2: #111116;
  --bg3: #18181f;
  --border: rgba(255,255,255,0.07);
  --border-hover: rgba(255,255,255,0.15);
  --text: #f0f0f4;
  --muted: #8a8a99;
  --accent: #6ee7b7;
  --accent2: #38bdf8;
  --accent3: #a78bfa;
  --accent4: #fb923c;
  --mono: 'DM Mono', monospace;
  --display: 'Syne', sans-serif;
}

html { scroll-behavior: smooth; }
body { background: var(--bg); color: var(--text); font-family: var(--mono); line-height: 1.6; }

nav {
  position: fixed; top: 0; width: 100%; z-index: 100;
  display: flex; align-items: center; justify-content: space-between;
  padding: 1.1rem 2.5rem;
  background: rgba(10,10,12,0.88);
  backdrop-filter: blur(14px);
  border-bottom: 1px solid var(--border);
}
.nav-logo { font-family: var(--display); font-size: 1.1rem; font-weight: 700; color: var(--text); letter-spacing: -0.02em; }
.nav-logo span { color: var(--accent); }
.nav-links { display: flex; gap: 2rem; }
.nav-links a { font-size: 0.78rem; color: var(--muted); text-decoration: none; letter-spacing: 0.08em; text-transform: uppercase; transition: color 0.2s; }
.nav-links a:hover { color: var(--accent); }

.hero {
  min-height: 100vh;
  display: flex; 
  flex-direction: column; 
  justify-content: center;
  padding: 0 2.5rem; /* Remove the 6rem top padding */
  max-width: 960px; 
  margin: 0 auto;
}
.hero-tag {
  display: inline-flex; align-items: center; gap: 0.5rem;
  font-size: 0.72rem; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--accent); margin-bottom: 1.8rem;
}
.hero-tag::before { content: ''; display: block; width: 28px; height: 1px; background: var(--accent); }
h1 {
  font-family: var(--display); font-size: clamp(2.8rem, 6vw, 5rem);
  font-weight: 800; line-height: 1.05; letter-spacing: -0.03em;
  color: var(--text); margin-bottom: 1.2rem;
}
h1 em { font-style: normal; color: var(--accent); }
.hero-sub { font-size: 0.95rem; color: var(--muted); max-width: 520px; line-height: 1.8; margin-bottom: 2.5rem; }
.hero-cta { display: flex; gap: 1rem; flex-wrap: wrap; }
.btn {
  display: inline-flex; align-items: center; gap: 0.5rem;
  padding: 0.65rem 1.4rem; font-size: 0.8rem; font-family: var(--mono);
  letter-spacing: 0.06em; text-decoration: none; border-radius: 4px;
  transition: all 0.2s; cursor: pointer; border: none;
}
.btn-primary { background: var(--accent); color: #0a0a0c; font-weight: 500; }
.btn-primary:hover { background: #34d399; }
.btn-outline { background: transparent; color: var(--muted); border: 1px solid var(--border-hover); }
.btn-outline:hover { color: var(--text); border-color: var(--text); }
.hero-grid {
  position: absolute; right: -40px; top: 50%; transform: translateY(-50%);
  width: 340px; height: 340px; opacity: 0.04; pointer-events: none;
  background-image:
    repeating-linear-gradient(var(--accent) 0, var(--accent) 1px, transparent 1px, transparent 40px),
    repeating-linear-gradient(90deg, var(--accent) 0, var(--accent) 1px, transparent 1px, transparent 40px);
}

section { padding: 5rem 2.5rem; max-width: 960px; margin: 0 auto; }
.section-label {
  font-size: 0.7rem; letter-spacing: 0.15em; text-transform: uppercase;
  color: var(--accent); margin-bottom: 0.6rem; display: flex; align-items: center; gap: 0.6rem;
}
.section-label::after { content: ''; flex: 1; height: 1px; background: var(--border); }
h2 { font-family: var(--display); font-size: clamp(1.6rem, 3vw, 2.2rem); font-weight: 700; letter-spacing: -0.02em; margin-bottom: 2.5rem; }

.about-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
.about-text { font-size: 0.9rem; color: var(--muted); line-height: 1.9; }
.about-text strong { color: var(--text); font-weight: 500; }
.about-stats { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; align-content: start; }
.stat-card { background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 1.1rem; }
.stat-num { font-family: var(--display); font-size: 1.8rem; font-weight: 700; color: var(--accent); line-height: 1.1; }
.stat-label { font-size: 0.72rem; color: var(--muted); margin-top: 0.3rem; letter-spacing: 0.06em; }

.filter-bar { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-bottom: 1.8rem; }
.filter-btn {
  font-size: 0.7rem; letter-spacing: 0.08em; text-transform: uppercase;
  padding: 0.3rem 0.9rem; border-radius: 3px; cursor: pointer;
  border: 1px solid var(--border); background: transparent; color: var(--muted);
  font-family: var(--mono); transition: all 0.15s;
}
.filter-btn:hover { border-color: var(--border-hover); color: var(--text); }
.filter-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(110,231,183,0.07); }

.projects-grid { display: grid; gap: 1px; background: var(--border); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.project-card {
  background: var(--bg2); padding: 1.8rem 2rem;
  display: grid; grid-template-columns: 1fr auto;
  gap: 1rem; align-items: start; transition: background 0.2s;
}
.project-card:hover { background: var(--bg3); }
.project-card.hidden { display: none; }

.tag {
  display: inline-block; font-size: 0.65rem; letter-spacing: 0.1em; text-transform: uppercase;
  padding: 2px 8px; border-radius: 3px; margin-bottom: 0.5rem; margin-right: 0.35rem; border: 1px solid;
}
.tag-green  { background: rgba(110,231,183,0.08); color: var(--accent);  border-color: rgba(110,231,183,0.2); }
.tag-blue   { background: rgba(56,189,248,0.08);  color: var(--accent2); border-color: rgba(56,189,248,0.2); }
.tag-purple { background: rgba(167,139,250,0.08); color: var(--accent3); border-color: rgba(167,139,250,0.2); }
.tag-orange { background: rgba(251,146,60,0.08);  color: var(--accent4); border-color: rgba(251,146,60,0.2); }

.project-title { font-family: var(--display); font-size: 1.05rem; font-weight: 600; margin-bottom: 0.4rem; }
.project-desc { font-size: 0.82rem; color: var(--muted); line-height: 1.75; max-width: 540px; }
.project-links { display: flex; flex-direction: column; gap: 0.45rem; align-items: flex-end; }
.project-link { font-size: 0.75rem; color: var(--muted); text-decoration: none; transition: color 0.2s; white-space: nowrap; }
.project-link:hover { color: var(--accent); }
.badge-coming {
  font-size: 0.62rem; letter-spacing: 0.1em; text-transform: uppercase;
  padding: 2px 7px; border-radius: 3px; color: var(--muted); border: 1px solid var(--border);
}

.skills-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.2rem; }
.skill-group { background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 1.3rem 1.4rem; }
.skill-group-title { font-size: 0.7rem; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); margin-bottom: 0.9rem; }
.skill-list { display: flex; flex-direction: column; gap: 0.45rem; }
.skill-item { font-size: 0.82rem; color: var(--muted); display: flex; align-items: center; gap: 0.5rem; }
.skill-item::before { content: ''; display: block; width: 4px; height: 4px; border-radius: 50%; background: var(--border-hover); flex-shrink: 0; }

.contact-wrap {
  background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
  padding: 2.5rem; display: flex; align-items: center; justify-content: space-between; gap: 2rem;
}
.contact-copy h3 { font-family: var(--display); font-size: 1.4rem; font-weight: 700; margin-bottom: 0.5rem; }
.contact-copy p { font-size: 0.85rem; color: var(--muted); max-width: 380px; line-height: 1.8; }
.contact-links { display: flex; flex-direction: column; gap: 0.75rem; align-items: flex-end; }
.contact-link { font-size: 0.8rem; color: var(--muted); text-decoration: none; display: flex; align-items: center; gap: 0.4rem; transition: color 0.2s; }
.contact-link:hover { color: var(--accent); }

footer { border-top: 1px solid var(--border); padding: 2rem 2.5rem; text-align: center; font-size: 0.72rem; color: var(--muted); max-width: 960px; margin: 0 auto; }

@media (max-width: 700px) {
  nav { padding: 1rem 1.25rem; }
  .nav-links { gap: 1.2rem; }
  .hero, section { padding-left: 1.25rem; padding-right: 1.25rem; }
  .about-grid { grid-template-columns: 1fr; }
  .skills-grid { grid-template-columns: 1fr 1fr; }
  .contact-wrap { flex-direction: column; }
  .contact-links { align-items: flex-start; }
  .hero-grid { display: none; }
  .project-card { grid-template-columns: 1fr; }
  .project-links { align-items: flex-start; flex-direction: row; flex-wrap: wrap; }
}
@media (max-width: 480px) {
  .skills-grid { grid-template-columns: 1fr; }
}
</style>
</head>

<body>

<nav>
  <div class="nav-links">
    <a href="#about">about</a>
    <a href="#projects">projects</a>
    <a href="#skills">skills</a>
    <a href="#contact">contact</a>
  </div>
</nav>

<div style="max-width:960px;margin:0 auto;position:relative;">
  <div class="hero-grid"></div>
</div>

<div class="hero">
  <div class="hero-tag">Senior Solutions Engineer</div>
  <h2><strong> Building at the<br>edge of <em>cloud</em><br>and complexity.</strong></h2>
  <p style="color:white;">I help organizations architect, migrate, and scale cloud infrastructure — turning technical depth into business outcomes across OCI, AWS, and Azure.</p>
  <div class="hero-cta">
    <a class="btn btn-primary" href="#projects">View my work</a>
  </div>
</div>

<section id="about">
  <div class="section-label">About</div>
  <h2>Who I am</h2>
  <div class="about-grid">
    <div class="about-text">
      <p style="color:white;">I'm a Senior Solutions Engineer at Oracle with 7 years in technology. Experience in cloud infrastructure, pre-sales engineering, AI, and security. I operate at the intersection of Sales, Customer Success, Product, and Engineering — translating complex technical architecture into clear business value.</p>
      <br>
      <p style="color:white;">My work spans cloud services and platforms — from VMware-to-OCI migrations and cloud-native architecture to GenAI tooling, security engineering, and agentic AI demos. I hold a BA in Computer Science & Mathematics from the University of Memphis.</p>
      <br>
    </div>
    <div class="about-stats">
      <div class="stat-card">
        <div class="stat-num">7</div>
        <div class="stat-label">Years in technology</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">3</div>
        <div class="stat-label">Cloud platforms (OCI, AWS, Azure)</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">2</div>
        <div class="stat-label">Published blogs</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">Security Fanatic</div>
        <div class="stat-label">from cloud securtiy to IAM</div>
      </div>
    </div>
  </div>
</section>

<section id="projects" style="padding-top:0;">
  <div class="section-label">Work</div>
  <h2>Featured projects</h2>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filter('all', this)">All</button>
    <button class="filter-btn" onclick="filter('cloud', this)">Cloud & OCI</button>
    <button class="filter-btn" onclick="filter('ai', this)">AI & ML</button>
    <button class="filter-btn" onclick="filter('security', this)">Security</button>
    <button class="filter-btn" onclick="filter('public-sector', this)">Public Sector</button>
  </div>

  <div class="projects-grid">
    <div class="project-card" data-tags="ai cloud">
      <div>
        <div><span class="tag tag-green">OCI</span><span class="tag tag-purple">Agentic AI</span><span class="tag tag-blue">MCP</span></div>
        <div class="project-title">Agentic AI Solution on OCI</div>
        <p style="color:white;" class="project-desc">End-to-end agentic AI demo built entirely on Oracle Cloud Infrastructure — includes a working agentic AI solution, architecture walkthrough, and an exploration of how MCP improves the workflow. Deployed with Terraform/IaC and a Node.js backend.</p>
      </div>
      <div class="project-links">
        <a class="project-link" href="https://objectstorage.us-ashburn-1.oraclecloud.com/p/e-Be2JuPDlD8UgxIxie6QqLfjGoeDMEuyLrL9CPAmDbbY8l9HTOKHvyyAksolxIP/n/idvum1adtfhr/b/AI-demos/o/oci-odaOCI-AgenticAI.mp4" target="_blank">Watch demo ↗</a>
      </div>
    </div>
    <div class="project-card" data-tags="ai public-sector">
      <div>
        <div><span class="tag tag-purple">AI</span><span class="tag tag-blue">Public Sector</span><span class="tag tag-green">OCI</span></div>
        <div class="project-title">Unlocking Public Sector Innovation with OCI & AI</div>
        <p style="color:white;" class="project-desc">Whitepaper exploring how state and local government agencies can overcome IT modernization challenges and unlock AI's potential using Oracle Cloud Infrastructure. Published on the Oracle AI & Data Science blog.</p>
      </div>
      <div class="project-links">
        <a class="project-link" href="https://blogs.oracle.com/ai-and-datascience/public-sector-innovation-oci-state-and-local-agencies" target="_blank">Read post ↗</a>
      </div>
    </div>
    <div class="project-card" data-tags="ai public-sector security">
      <div>
        <div><span class="tag tag-purple">AI/ML</span><span class="tag tag-orange">Security</span><span class="tag tag-blue">Public Sector</span></div>
        <div class="project-title">AI & ML Security in the Public Sector</div>
        <p style="color:white;" class="project-desc">Blog post on the accelerating adoption of AI and ML across government — covering how Oracle Cloud's AI/ML solutions address data security, scalability, and compliance for public agencies. Explores automation, citizen services, and policy-making at scale.</p>
      </div>
      <div class="project-links">
        <a class="project-link" href="https://blogs.oracle.com/cloud-infrastructure/post/emphasis-on-aiml-security-in-the-public-sector" target="_blank">Read post ↗</a>
      </div>
    </div>
    <div class="project-card" data-tags="cloud security">
      <div>
        <div><span class="tag tag-green">OCI</span><span class="tag tag-orange">IAM</span><span class="tag tag-blue">WAF</span></div>
        <div class="project-title">Secure Cloud Architectures: OCI IAM & WAF</div>
        <p style="color:white;" class="project-desc">Designed a comprehensive cloud security architecture using OCI Cloud Guard, IAM policies, and Web Application Firewalls. Enforced RBAC through granular least-privilege policies and configured WAF rules to defend against SQLi, XSS, and DDoS threats.</p>
      </div>
      <div class="project-links">
        <a class="project-link" href="#contact">Inquire ↗</a>
      </div>
    </div>
    <div class="project-card" data-tags="cloud security">
      <div>
        <div><span class="tag tag-orange">WAF</span><span class="tag tag-green">OCI</span><span class="tag tag-blue">Networking</span></div>
        <div class="project-title">Deploying an OCI Web Application Firewall</div>
        <p style="color:white;" class="project-desc">Step-by-step guide configuring a load balancer for a web server on OCI Compute and securing it with OCI WAF as part of a layered security strategy. Blog post pending Oracle publishing review.</p>
      </div>
      <div class="project-links">
        <span class="badge-coming">Coming soon</span>
      </div>
    </div>
    <div class="project-card" data-tags="cloud">
      <div>
        <div><span class="tag tag-green">OCI</span><span class="tag tag-blue">VMware</span><span class="tag tag-purple">Migration</span></div>
        <div class="project-title">VMware-to-OCI Migration Framework</div>
        <p style="color:white;" class="project-desc">RVTools-based discovery pipeline for CPU sizing ratios across Intel Xeon generations, OCVS vs. cloud-native cost estimates, and VDI scoping. Delivered in enterprise pre-sales engagements with detailed migration path comparisons (RackWare vs. Cloud Engineering Services).</p>
      </div>
      <div class="project-links">
        <a class="project-link" href="#contact">Inquire ↗</a>
      </div>
    </div>
    <div class="project-card" data-tags="security">
      <div>
        <div><span class="tag tag-orange">Malware Analysis</span><span class="tag tag-blue">OSINT</span><span class="tag tag-purple">Security</span></div>
        <div class="project-title">Static & Dynamic Malware Analysis</div>
        <p style="color:white;" class="project-desc">Two-part analysis of a keylogger executable and Python script. Static: PE header inspection, hash verification via VirusTotal, IOC extraction. Dynamic: Windows Defender evasion via obfuscation and packing, real-time behavior observation in an isolated VM, and persistence mechanism identification.</p>
      </div>
      <div class="project-links">
        <a class="project-link" href="https://youtu.be/vjDuOHOMlJc?si=TqcFx6O982eB3LV_" target="_blank">Static demo ↗</a>
        <a class="project-link" href="https://youtu.be/RvHy83w9o5A?si=A4rtUoZElggDOkA1" target="_blank">Dynamic demo ↗</a>
      </div>
    </div>
    <div class="project-card" data-tags="cloud ai">
      <div>
        <div><span class="tag tag-green">Oracle APEX</span><span class="tag tag-blue">SQL</span><span class="tag tag-purple">App Dev</span></div>
        <div class="project-title">Coffee Chats — OCI Matching App</div>
        <p style="color:white;" class="project-desc">Matching application built in Oracle APEX to facilitate weekly virtual coffee chats. Implemented random pairing algorithms in SQL to prevent repeat matches and factor in user preferences. Designed and optimized queries for profile retrieval, match history, and pairing status at scale.</p>
      </div>
      <div class="project-links">
        <a class="project-link" href="#contact">Inquire ↗</a>
      </div>
    </div>
    <div class="project-card" data-tags="ai">
      <div>
        <div><span class="tag tag-purple">AI</span><span class="tag tag-blue">Education</span><span class="tag tag-green">Slides</span></div>
        <div class="project-title">Cloud & AI Foundations Presentation</div>
        <p style="color:white;" class="project-desc"> A 40–45 minute talk covering IaaS/PaaS/SaaS, deployment models, AI umbrella layers, agentic AI, and AI ethics — designed for entry-level finance and data professionals. Includes full presenter script and custom design system.</p>
      </div>
      <div class="project-links">
        <a class="project-link" href="#contact">Request deck ↗</a>
      </div>
    </div>

  </div>
</section>

<section id="skills" style="padding-top:0;">
  <div class="section-label">Skills</div>
  <h2>Technical stack</h2>
  <div class="skills-grid">
    <div class="skill-group">
      <div class="skill-group-title">Cloud platforms</div>
      <div class="skill-list">
        <div class="skill-item">Oracle Cloud Infrastructure (OCI)</div>
        <div class="skill-item">Amazon Web Services (AWS)</div>
        <div class="skill-item">Microsoft Azure</div>
        <div class="skill-item">VMware / OCVS</div>
      </div>
    </div>
    <div class="skill-group">
      <div class="skill-group-title">Infrastructure & DevOps</div>
      <div class="skill-list">
        <div class="skill-item">Terraform / IaC</div>
        <div class="skill-item">Kubernetes</div>
        <div class="skill-item">Scripting</div>
        <div class="skill-item">RVTools / migration tooling</div>
      </div>
    </div>
    <div class="skill-group">
      <div class="skill-group-title">Security engineering</div>
      <div class="skill-list">
        <div class="skill-item">IAM & RBAC architecture</div>
        <div class="skill-item">Web Application Firewall (WAF)</div>
        <div class="skill-item">Static & dynamic malware analysis</div>
        <div class="skill-item">Zero-trust principles</div>
      </div>
    </div>
    <div class="skill-group">
      <div class="skill-group-title">AI & Emerging tech</div>
      <div class="skill-list">
        <div class="skill-item">Agentic AI / MCP</div>
        <div class="skill-item">GenAI tooling & integration</div>
        <div class="skill-item">AI ethics frameworks</div>
        <div class="skill-item">LLM application architecture</div>
      </div>
    </div>
    <div class="skill-group">
      <div class="skill-group-title">Pre-sales & SE</div>
      <div class="skill-list">
        <div class="skill-item">Discovery & solutioning</div>
        <div class="skill-item">Technical demos & PoCs</div>
        <div class="skill-item">RFP / proposal writing</div>
        <div class="skill-item">Competitive positioning</div>
      </div>
    </div>
    <div class="skill-group">
      <div class="skill-group-title">Cross-functional</div>
      <div class="skill-list">
        <div class="skill-item">Sales & customer success</div>
        <div class="skill-item">Technical content & blogging</div>
        <div class="skill-item">Technical education & speaking</div>
      </div>
    </div>
  </div>
</section>

<section id="contact" style="padding-top:0;">
  <div class="section-label">Contact</div>
  <h2>Get in touch</h2>
  <div class="contact-wrap">
    <div class="contact-copy">
      <h3>Let's work together.</h3>
    </div>
    <div class="contact-links">
      <a class="contact-link" href="https://mkaynz.github.io" target="_blank">Portfolio ↗</a>
      <a class="contact-link" href="https://linkedin.com" target="_blank">LinkedIn ↗</a>
      <a class="contact-link" href="mailto:hollidaymckenzie80@gmail.com">hollidaymckenzie80@gmail.com ↗</a>
    </div>
  </div>
</section>


<script>
function filter(tag, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.project-card').forEach(card => {
    if (tag === 'all') {
      card.classList.remove('hidden');
    } else {
      const tags = (card.dataset.tags || '').split(' ');
      card.classList.toggle('hidden', !tags.includes(tag));
    }
  });
}
</script>

</body>
</html>
