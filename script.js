/**
 * PhishGuard — Cybersecurity Awareness Training Website
 * Interactive Controller & Logic Engine
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  /* ==========================================================================
     1. READING PROGRESS BAR & SCROLL HANDLING
     ========================================================================== */
  const progressBar = document.getElementById('readingProgressBar');
  const siteHeader = document.getElementById('siteHeader');
  const navLinks = document.querySelectorAll('.nav-link');
  const sections = document.querySelectorAll('section[id]');

  window.addEventListener('scroll', () => {
    // Progress bar fill
    const winScroll = document.documentElement.scrollTop || document.body.scrollTop;
    const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    const scrolled = height > 0 ? (winScroll / height) * 100 : 0;
    if (progressBar) {
      progressBar.style.width = `${scrolled}%`;
    }

    // Header styling on scroll
    if (siteHeader) {
      if (winScroll > 30) {
        siteHeader.classList.add('scrolled');
      } else {
        siteHeader.classList.remove('scrolled');
      }
    }

    // Active Section Tracking
    let currentSectionId = '';
    sections.forEach(section => {
      const sectionTop = section.offsetTop - 120;
      const sectionHeight = section.offsetHeight;
      if (winScroll >= sectionTop && winScroll < sectionTop + sectionHeight) {
        currentSectionId = section.getAttribute('id');
      }
    });

    if (currentSectionId) {
      navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === `#${currentSectionId}`) {
          link.classList.add('active');
        }
      });
    }
  });

  /* ==========================================================================
     2. MOBILE NAVIGATION DRAWER
     ========================================================================== */
  const menuToggleBtn = document.getElementById('menuToggleBtn');
  const mobileDrawer = document.getElementById('mobileDrawer');
  const mobileNavLinks = document.querySelectorAll('.mobile-nav-link, .mobile-quiz-btn');

  if (menuToggleBtn && mobileDrawer) {
    menuToggleBtn.addEventListener('click', () => {
      const isOpen = mobileDrawer.classList.toggle('open');
      menuToggleBtn.classList.toggle('open');
      menuToggleBtn.setAttribute('aria-expanded', isOpen);
      mobileDrawer.setAttribute('aria-hidden', !isOpen);
    });

    mobileNavLinks.forEach(link => {
      link.addEventListener('click', () => {
        mobileDrawer.classList.remove('open');
        menuToggleBtn.classList.remove('open');
        menuToggleBtn.setAttribute('aria-expanded', 'false');
        mobileDrawer.setAttribute('aria-hidden', 'true');
      });
    });
  }

  /* ==========================================================================
     3. INTERACTIVE URL ANATOMY INSPECTOR TOOL
     ========================================================================== */
  const urlInspectInput = document.getElementById('urlInspectInput');
  const urlInspectBtn = document.getElementById('urlInspectBtn');
  const samplePills = document.querySelectorAll('.btn-pill-sample');
  const tokenStream = document.getElementById('urlTokenStream');
  const verdictBadge = document.getElementById('verdictBadge');
  const verdictIcon = document.getElementById('verdictIcon');
  const verdictTitle = document.getElementById('verdictTitle');
  const verdictReason = document.getElementById('verdictReason');
  const valDomain = document.getElementById('valDomain');
  const valTarget = document.getElementById('valTarget');
  const valProtocol = document.getElementById('valProtocol');
  const valAction = document.getElementById('valAction');

  const urlPresets = {
    'scam-bank': {
      url: 'https://chase-bank.security-verification-portal.com/login',
      protocol: 'https://',
      subdomain: 'chase-bank',
      domain: 'security-verification-portal',
      tld: '.com',
      path: '/login',
      isPhish: true,
      target: 'Chase Bank',
      reason: 'The actual registered domain is "security-verification-portal.com". The attacker placed "chase-bank" into the subdomain to trick users into believing it belongs to Chase Bank.',
      action: 'Do not click or enter credentials! Close page immediately.'
    },
    'scam-subdomain': {
      url: 'https://paypal.com.customer-support-alert.xyz/verify',
      protocol: 'https://',
      subdomain: 'paypal.com',
      domain: 'customer-support-alert',
      tld: '.xyz',
      path: '/verify',
      isPhish: true,
      target: 'PayPal',
      reason: 'Classic Subdomain Obfuscation: "paypal.com" is merely a prefix subdomain. The server is owned by "customer-support-alert.xyz", a dangerous and untrusted domain extension.',
      action: 'High-risk phishing attack. Never authenticate or submit billing info.'
    },
    'scam-typo': {
      url: 'https://rnicrosoft-office365-login.net/auth',
      protocol: 'https://',
      subdomain: '',
      domain: 'rnicrosoft-office365-login',
      tld: '.net',
      path: '/auth',
      isPhish: true,
      target: 'Microsoft 365',
      reason: 'Typosquatting Trick: The letter sequence "r" followed by "n" looks nearly identical to "m" ("rn" vs "m"). The real domain is microsoft.com.',
      action: 'Fraudulent credential harvesting site. Report to IT Security.'
    },
    'safe-bank': {
      url: 'https://www.chase.com/personal/banking',
      protocol: 'https://',
      subdomain: 'www',
      domain: 'chase',
      tld: '.com',
      path: '/personal/banking',
      isPhish: false,
      target: 'Chase (Official)',
      reason: 'This is the genuine registered domain of JPMorgan Chase & Co. ("chase.com") with official root ownership and valid institutional certificates.',
      action: 'Verified official domain. Safe to proceed.'
    }
  };

  function analyzeUrl(urlString) {
    let raw = urlString.trim();
    if (!raw.startsWith('http://') && !raw.startsWith('https://')) {
      raw = 'https://' + raw;
    }

    try {
      const parsed = new URL(raw);
      const protocol = parsed.protocol + '//';
      const host = parsed.hostname;
      const path = parsed.pathname + (parsed.search || '');

      // Parse domain parts
      const parts = host.split('.');
      let tld = '';
      let sld = '';
      let sub = '';

      if (parts.length >= 2) {
        tld = '.' + parts[parts.length - 1];
        sld = parts[parts.length - 2];
        if (parts.length > 2) {
          sub = parts.slice(0, parts.length - 2).join('.');
        }
      } else {
        sld = host;
      }

      // Detect phishing indicators
      const fullDomain = `${sld}${tld}`.toLowerCase();
      const suspiciousTLDs = ['.xyz', '.top', '.cam', '.tk', '.live', '.biz', '.click'];
      const brandKeywords = ['paypal', 'chase', 'apple', 'microsoft', 'google', 'netflix', 'amazon', 'wellsfargo', 'bankofamerica'];
      
      let isPhish = false;
      let targetDetected = 'Unknown / Custom';
      let reasonMsg = '';

      // Check if brand is in subdomain while sld is different
      const foundInSub = brandKeywords.find(b => sub.toLowerCase().includes(b));
      const foundInSld = brandKeywords.find(b => sld.toLowerCase().includes(b));

      if (foundInSub && !sld.toLowerCase().includes(foundInSub)) {
        isPhish = true;
        targetDetected = foundInSub.toUpperCase();
        reasonMsg = `Deceptive Subdomain: The brand "${foundInSub}" appears in the subdomain, but the actual hosting domain is "${fullDomain}". This is a classic phishing lure.`;
      } else if (sld.toLowerCase().includes('rn') && (sld.includes('rnicrosoft') || sld.includes('amazrn'))) {
        isPhish = true;
        targetDetected = 'Microsoft / Brand Typosquat';
        reasonMsg = `Typosquatting Detected: The letters "r" and "n" are used to visually imitate the letter "m". The real domain is not "${fullDomain}".`;
      } else if (sld.includes('security') || sld.includes('verify') || sld.includes('update') || sld.includes('login-auth')) {
        isPhish = true;
        targetDetected = foundInSld ? foundInSld.toUpperCase() : 'Generic Credential Harvester';
        reasonMsg = `Suspicious Domain Pattern: The domain "${fullDomain}" utilizes high-risk security lure keywords and is not an authentic brand portal.`;
      } else if (suspiciousTLDs.includes(tld)) {
        isPhish = true;
        targetDetected = 'Untrusted Top-Level Domain';
        reasonMsg = `High-Risk TLD: The extension "${tld}" has high abuse rates and is virtually never used by reputable financial institutions.`;
      } else if (fullDomain === 'chase.com' || fullDomain === 'paypal.com' || fullDomain === 'microsoft.com' || fullDomain === 'google.com') {
        isPhish = false;
        targetDetected = fullDomain.toUpperCase() + ' (Official)';
        reasonMsg = `Verified Registered Domain: "${fullDomain}" is the authentic primary domain of the organization.`;
      } else {
        // Generic verdict
        isPhish = false;
        targetDetected = fullDomain;
        reasonMsg = `Domain structure appears standard, but always verify sender context and navigate through saved bookmarks if logging into sensitive accounts.`;
      }

      // Render Token Pills
      tokenStream.innerHTML = `
        <div class="token-pill protocol">
          <span class="token-name">Protocol</span>
          <span class="token-val">${protocol}</span>
        </div>
        ${sub ? `
          <div class="token-pill ${isPhish && foundInSub ? 'danger' : ''}">
            <span class="token-name">Subdomain ${isPhish && foundInSub ? '(Deceptive)' : ''}</span>
            <span class="token-val">${sub}</span>
          </div>
        ` : ''}
        <div class="token-pill ${isPhish ? 'danger' : 'safe'}">
          <span class="token-name">Registered Domain (Real Owner)</span>
          <span class="token-val">${sld}${tld}</span>
        </div>
        <div class="token-pill">
          <span class="token-name">Path / Query</span>
          <span class="token-val">${path || '/'}</span>
        </div>
      `;

      // Update Verdict Box
      if (isPhish) {
        verdictBadge.className = 'verdict-status-badge danger';
        verdictIcon.textContent = '🚨';
        verdictTitle.textContent = 'High Phishing Risk Detected';
        valDomain.className = 'v-val text-danger';
        valAction.className = 'v-val text-danger';
        valAction.textContent = 'Do not click or enter credentials! Close page.';
      } else {
        verdictBadge.className = 'verdict-status-badge safe';
        verdictIcon.textContent = '🛡️';
        verdictTitle.textContent = 'Authentic / Low Risk Domain';
        valDomain.className = 'v-val text-success';
        valAction.className = 'v-val text-success';
        valAction.textContent = 'Domain appears legitimate. Verify context before logging in.';
      }

      verdictReason.textContent = reasonMsg;
      valDomain.textContent = `${sld}${tld}`;
      valTarget.textContent = targetDetected;
      valProtocol.textContent = `${protocol.toUpperCase()} ${protocol === 'https://' ? '(Encrypted connection)' : '(Unencrypted - Insecure)'}`;

    } catch (e) {
      tokenStream.innerHTML = `<span class="text-danger">Invalid URL format entered. Please enter a valid address (e.g. https://example.com/login).</span>`;
    }
  }

  // Trigger default analysis on page load
  if (urlInspectInput) {
    analyzeUrl(urlInspectInput.value);

    urlInspectBtn.addEventListener('click', () => {
      analyzeUrl(urlInspectInput.value);
    });

    urlInspectInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        analyzeUrl(urlInspectInput.value);
      }
    });
  }

  samplePills.forEach(pill => {
    pill.addEventListener('click', () => {
      const sampleKey = pill.getAttribute('data-sample');
      if (urlPresets[sampleKey]) {
        urlInspectInput.value = urlPresets[sampleKey].url;
        analyzeUrl(urlPresets[sampleKey].url);
      }
    });
  });

  /* ==========================================================================
     4. REALISTIC TRAINING EXAMPLES (SIMULATED INBOX & SMS)
     ========================================================================== */
  const simTabs = document.querySelectorAll('.sim-tab');
  const simBodyContent = document.getElementById('simBodyContent');
  const simThreatLabel = document.getElementById('simThreatLabel');
  const simStatusIndicator = document.getElementById('simStatusIndicator');
  const simExplanationFooter = document.getElementById('simExplanationFooter');
  const toggleRedFlagsBtn = document.getElementById('toggleRedFlagsBtn');
  const toggleRedFlagsText = document.getElementById('toggleRedFlagsText');

  let areRedFlagsVisible = true;
  let currentScenarioKey = 'bank-email';

  const scenarios = {
    'bank-email': {
      isPhish: true,
      threatLabel: 'PHISHING EMAIL SIMULATION (FICTIONAL LURE)',
      render: () => `
        <div class="email-client-mock">
          <div class="email-header-meta">
            <div class="email-row">
              <span class="email-label">From:</span>
              <span class="email-val">
                Chase Security Center 
                <span class="red-flag-target ${areRedFlagsVisible ? '' : 'hidden-flags'}" data-flag="sender">
                  &lt;alert-service@chase-security-verify.net&gt;
                </span>
              </span>
            </div>
            <div class="email-row">
              <span class="email-label">To:</span>
              <span class="email-val">user@example.com</span>
            </div>
            <div class="email-row">
              <span class="email-label">Date:</span>
              <span class="email-val">Today, 09:14 AM</span>
            </div>
            <div class="email-row">
              <span class="email-label">Subject:</span>
              <span class="email-subject">
                <span class="red-flag-target ${areRedFlagsVisible ? '' : 'hidden-flags'}" data-flag="urgency">
                  URGENT: Your Account Has Been Locked Due to Suspicious Activity [Action Required in 24 Hours]
                </span>
              </span>
            </div>
          </div>
          <div class="email-body">
            <p>
              <span class="red-flag-target ${areRedFlagsVisible ? '' : 'hidden-flags'}" data-flag="greeting">
                Dear Valued Customer,
              </span>
            </p>
            <p>
              We detected an unauthorized access attempt to your online banking profile from an unknown device in Moscow, Russia on October 11, 2026. For your immediate safety, your checking and savings privileges have been restricted.
            </p>
            <p>
              To restore access and avoid a permanent $150 security lock fee, you must verify your identity immediately:
            </p>
            <p style="margin: 1.5rem 0;">
              <span class="red-flag-target ${areRedFlagsVisible ? '' : 'hidden-flags'}" data-flag="link" style="display:inline-block; padding: 0.6rem 1.2rem; background: #2563eb; color: #fff; border-radius: 6px; text-decoration: none; font-weight: bold;">
                Verify Your Account Now &gt;&gt;
              </span>
              <br>
              <small style="color: #94a3b8; display: block; margin-top: 0.4rem; font-family: monospace;">
                Hovering reveals: https://chase-login-auth.xyz/verify-identity?token=8912
              </small>
            </p>
            <p>
              If verification is not completed within <strong>24 hours</strong>, your account balance will be permanently frozen pending legal review.
            </p>
            <p style="color: #64748b; font-size: 0.85rem; border-top: 1px solid #1e293b; padding-top: 1rem; margin-top: 1.5rem;">
              © 2026 JPMorgan Chase &amp; Co. Member FDIC.
            </p>
          </div>
        </div>
      `,
      defaultExp: {
        icon: 'alert',
        title: 'High-Threat Phishing Email: 4 Major Red Flags',
        desc: 'Click on any highlighted red flag above to inspect why it exposes the attacker. Notice the spoofed sender domain, extreme urgency, generic greeting, and fraudulent .xyz link.'
      },
      flagExplanations: {
        sender: {
          icon: 'alert',
          title: 'Red Flag: Spoofed Sender Domain',
          desc: 'The display name claims "Chase", but the actual domain after @ is "chase-security-verify.net". Official Chase emails only originate from "@chase.com". Anyone can register lookalike .net domains.'
        },
        urgency: {
          icon: 'alert',
          title: 'Red Flag: Fabricated Urgency & Threat',
          desc: 'The subject creates artificial panic ("Action Required in 24 Hours", "Locked"). Attackers induce panic to force hasty clicks before the user has time to evaluate.'
        },
        greeting: {
          icon: 'alert',
          title: 'Red Flag: Impersonal Generic Greeting',
          desc: '"Dear Valued Customer" is a hallmark of mass phishing spam. Legitimate banks address you by your verified legal first and last name.'
        },
        link: {
          icon: 'alert',
          title: 'Red Flag: Deceptive Destination URL',
          desc: 'The button link points to "chase-login-auth.xyz". Attackers use obscure TLDs (.xyz) and bogus domains to host credential harvesting clone portals.'
        }
      }
    },

    'delivery-smish': {
      isPhish: true,
      threatLabel: 'SMISHING (SMS PHISHING) SIMULATION',
      render: () => `
        <div class="smartphone-mock">
          <div class="phone-top-notch"></div>
          <div class="sms-thread-header">
            <div class="sms-contact-name">Postal Dispatch Courier</div>
            <div class="sms-contact-phone">
              <span class="red-flag-target ${areRedFlagsVisible ? '' : 'hidden-flags'}" data-flag="sms-sender">
                +1 (833) 940-1829
              </span>
            </div>
          </div>
          <div class="sms-bubble">
            <span class="red-flag-target ${areRedFlagsVisible ? '' : 'hidden-flags'}" data-flag="sms-fee">
              [USPS Alert]: Your package #US940021 could not be delivered due to an incorrect street address.
            </span>
            A redelivery fee of $1.95 is required. Please update your delivery details within 12 hours at 
            <span class="red-flag-target ${areRedFlagsVisible ? '' : 'hidden-flags'}" data-flag="sms-link" style="color: #38bdf8; text-decoration: underline;">
              https://usps-track-portal.cam/confirm
            </span> 
            or package will be returned to sender.
          </div>
          <div class="sms-timestamp">Today 2:41 PM</div>
        </div>
      `,
      defaultExp: {
        icon: 'alert',
        title: 'Smishing (SMS) Delivery Scam',
        desc: 'Attackers prey on people expecting packages. Inspect the random toll-free sender number, the bogus redelivery fee request, and the unofficial .cam domain.'
      },
      flagExplanations: {
        'sms-sender': {
          icon: 'alert',
          title: 'Red Flag: Suspicious Toll-Free Sender',
          desc: 'Official postal services dispatch notifications via standardized 5-digit short codes (e.g. 28777 for USPS), not random 10-digit 833 VOIP numbers.'
        },
        'sms-fee': {
          icon: 'alert',
          title: 'Red Flag: Small Processing Fee Trap',
          desc: 'Requiring a "$1.95 fee" is a credit card harvesting trap. Once you enter your payment details on the fake form, attackers bill recurring fraudulent charges.'
        },
        'sms-link': {
          icon: 'alert',
          title: 'Red Flag: Fake Courier URL',
          desc: 'The link leads to "usps-track-portal.cam". Genuine USPS tracking exclusively takes place on "tools.usps.com". Never click tracking links in unprompted SMS messages.'
        }
      }
    },

    'it-spear': {
      isPhish: true,
      threatLabel: 'SPEAR PHISHING (INTERNAL CORPORATE IMPERSONATION)',
      render: () => `
        <div class="email-client-mock">
          <div class="email-header-meta">
            <div class="email-row">
              <span class="email-label">From:</span>
              <span class="email-val">
                Internal IT Helpdesk
                <span class="red-flag-target ${areRedFlagsVisible ? '' : 'hidden-flags'}" data-flag="it-sender">
                  &lt;it-support@corp-global-sso.co&gt;
                </span>
              </span>
            </div>
            <div class="email-row">
              <span class="email-label">Subject:</span>
              <span class="email-subject">
                <span class="red-flag-target ${areRedFlagsVisible ? '' : 'hidden-flags'}" data-flag="it-urgent">
                  MANDATORY: Employee Password Expiration Notice [Ticket #90144]
                </span>
              </span>
            </div>
          </div>
          <div class="email-body">
            <p>Hello Team Member,</p>
            <p>
              Your corporate Active Directory and Office 365 credentials will expire today at 6:00 PM EST in compliance with company security policy.
            </p>
            <p>
              To maintain uninterrupted access to VPN, email, and Slack, you must retain your current password immediately via the self-service SSO portal:
            </p>
            <p>
              <span class="red-flag-target ${areRedFlagsVisible ? '' : 'hidden-flags'}" data-flag="it-link" style="color: #38bdf8; text-decoration: underline; font-weight: bold;">
                Keep My Same Password (One-Click Authentication)
              </span>
            </p>
            <p>
              <span class="red-flag-target ${areRedFlagsVisible ? '' : 'hidden-flags'}" data-flag="it-mfa">
                Note: You will be asked to enter your password and approve the Duo/Okta push notification to complete synchronization.
              </span>
            </p>
            <p style="color: #64748b; font-size: 0.85rem;">
              IT Infrastructure &amp; Security Services
            </p>
          </div>
        </div>
      `,
      defaultExp: {
        icon: 'alert',
        title: 'Spear Phishing: Corporate SSO Theft Lure',
        desc: 'Attackers impersonate workplace IT staff. They use fake password expiration notices and push-fatigue or proxy phishing to steal corporate credentials.'
      },
      flagExplanations: {
        'it-sender': {
          icon: 'alert',
          title: 'Red Flag: Non-Corporate Domain',
          desc: 'The domain "corp-global-sso.co" is registered by an outsider. Internal company IT only sends emails from the company\'s exact primary domain.'
        },
        'it-urgent': {
          icon: 'alert',
          title: 'Red Flag: Artificial Expiration Deadline',
          desc: 'Claiming your password expires today at 6:00 PM creates false urgency. Corporate IT systems notify employees weeks in advance inside your OS login.'
        },
        'it-link': {
          icon: 'alert',
          title: 'Red Flag: "Keep Same Password" Illusion',
          desc: 'IT systems never have a button allowing you to "keep your same password" when an expiration policy triggers. This is a lure to capture current credentials.'
        },
        'it-mfa': {
          icon: 'alert',
          title: 'Red Flag: Proxy MFA Interception',
          desc: 'The attacker prepares you to approve an MFA push notification so that when you enter your password, the attacker can log in live and hijack your session.'
        }
      }
    },

    'legit-email': {
      isPhish: false,
      threatLabel: 'SAFE LEGITIMATE EMAIL (VERIFIED BENCHMARK)',
      render: () => `
        <div class="email-client-mock" style="border-color: rgba(16, 185, 129, 0.4);">
          <div class="email-header-meta" style="background: rgba(16, 185, 129, 0.08);">
            <div class="email-row">
              <span class="email-label">From:</span>
              <span class="email-val">
                PayPal
                <span class="safe-flag-target" data-flag="safe-sender">
                  &lt;service@paypal.com&gt; [DKIM &amp; SPF: PASS]
                </span>
              </span>
            </div>
            <div class="email-row">
              <span class="email-label">To:</span>
              <span class="email-val">Alex Johnson &lt;alex.j@example.com&gt;</span>
            </div>
            <div class="email-row">
              <span class="email-label">Subject:</span>
              <span class="email-subject">
                <span class="safe-flag-target" data-flag="safe-subject">
                  Your monthly account statement is ready to view
                </span>
              </span>
            </div>
          </div>
          <div class="email-body">
            <p>
              <span class="safe-flag-target" data-flag="safe-greeting">
                Hello Alex Johnson,
              </span>
            </p>
            <p>
              Your monthly PayPal transaction statement for September 2026 is now available.
            </p>
            <p>
              <span class="safe-flag-target" data-flag="safe-body">
                To view your statement, please open your browser, visit paypal.com directly, and log in to your account, or check your PayPal mobile app.
              </span>
            </p>
            <p>
              PayPal will never ask you to reply with your password, full credit card details, or authentication codes in an email.
            </p>
            <p style="color: #64748b; font-size: 0.85rem; border-top: 1px solid #1e293b; padding-top: 1rem; margin-top: 1.5rem;">
              © 2026 PayPal, Inc. All rights reserved. PayPal is located at 2211 N. First St., San Jose, CA 95131.
            </p>
          </div>
        </div>
      `,
      defaultExp: {
        icon: 'pass',
        title: 'Verified Legitimate Communication Benchmark',
        desc: 'Notice how a legitimate company communicates: Authenticated domain (@paypal.com), personal name greeting, no coercive deadlines, and asks the user to navigate independently.'
      },
      flagExplanations: {
        'safe-sender': {
          icon: 'pass',
          title: 'Safe Factor: Authenticated Sender Domain',
          desc: 'The email originates from "@paypal.com" with valid SPF, DKIM, and DMARC cryptographic signatures passing verification.'
        },
        'safe-subject': {
          icon: 'pass',
          title: 'Safe Factor: Informational Subject',
          desc: 'No threats of account deletion, no artificial countdowns, and no alarming warnings.'
        },
        'safe-greeting': {
          icon: 'pass',
          title: 'Safe Factor: Personalized Greeting',
          desc: 'The email addresses the recipient by their exact registered name (Alex Johnson), not "Dear Customer".'
        },
        'safe-body': {
          icon: 'pass',
          title: 'Safe Factor: Independent Navigation Encouraged',
          desc: 'Best-practice security design: Legitimate organizations instruct users to navigate to the official app or website directly rather than forcing clicks on suspicious inline links.'
        }
      }
    }
  };

  function renderScenario(scenarioKey) {
    const sc = scenarios[scenarioKey];
    currentScenarioKey = scenarioKey;

    // Status label
    simThreatLabel.textContent = sc.threatLabel;
    const threatDot = simStatusIndicator.querySelector('.threat-dot');
    if (sc.isPhish) {
      threatDot.className = 'threat-dot dangerous';
    } else {
      threatDot.className = 'threat-dot safe';
    }

    // Render body
    simBodyContent.innerHTML = sc.render();

    // Default explanation
    updateExplanation(sc.defaultExp.icon, sc.defaultExp.title, sc.defaultExp.desc);

    // Bind hotspot clicks
    bindHotspotEvents();
  }

  function updateExplanation(iconType, title, desc) {
    simExplanationFooter.innerHTML = `
      <div class="explanation-banner-inner">
        <div class="exp-badge-icon ${iconType}">
          ${iconType === 'alert' ? '⚠️' : '🛡️'}
        </div>
        <div class="exp-text-group">
          <h5>${title}</h5>
          <p>${desc}</p>
        </div>
      </div>
    `;
  }

  function bindHotspotEvents() {
    const targets = simBodyContent.querySelectorAll('.red-flag-target, .safe-flag-target');
    targets.forEach(target => {
      target.addEventListener('click', () => {
        // Remove active class from others
        targets.forEach(t => t.classList.remove('active-target'));
        target.classList.add('active-target');

        const flagKey = target.getAttribute('data-flag');
        const sc = scenarios[currentScenarioKey];
        if (sc.flagExplanations && sc.flagExplanations[flagKey]) {
          const exp = sc.flagExplanations[flagKey];
          updateExplanation(exp.icon, exp.title, exp.desc);
        }
      });
    });
  }

  // Sidebar scenario switcher
  simTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      simTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const scKey = tab.getAttribute('data-scenario');
      renderScenario(scKey);
    });
  });

  // Toggle Red Flags Visibility
  if (toggleRedFlagsBtn) {
    toggleRedFlagsBtn.addEventListener('click', () => {
      areRedFlagsVisible = !areRedFlagsVisible;
      toggleRedFlagsText.textContent = areRedFlagsVisible ? 'Hide Explanations' : 'Show Red Flag Hints';
      renderScenario(currentScenarioKey);
    });
  }

  // Initial Scenario Render
  renderScenario('bank-email');

  /* ==========================================================================
     5. INTERACTIVE QUIZ ENGINE (10+ SCENARIO-BASED QUESTIONS)
     ========================================================================== */
  const quizQuestions = [
    {
      category: 'Email Phishing Detection',
      question: 'You receive an urgent email from "PayPal Security Team" warning that your account is locked due to suspicious logins. What is the safest first action?',
      options: [
        'Click the "Unlock Account Now" button in the email and change your password immediately.',
        'Ignore the email and reply with your phone number so support can call you.',
        'Open a new browser tab, manually type "paypal.com" or open the official app, and check your security notifications.',
        'Forward the email to all your coworkers to ask if their accounts are also locked.'
      ],
      correctIndex: 2,
      explanation: 'Always navigate independently. By opening a fresh browser tab and typing the known official URL directly (or opening the official mobile app), you bypass any deceptive links designed to harvest credentials.'
    },
    {
      category: 'Fake Website & URL Anatomy',
      question: 'Which of the following URLs is the genuine website belonging to Apple?',
      options: [
        'https://apple.com.security-id-verification.org/login',
        'https://appleid.apple.com',
        'http://apple-support-portal.net/auth',
        'https://applе.com (using Cyrillic character "е")'
      ],
      correctIndex: 1,
      explanation: 'In "appleid.apple.com", the registered domain is "apple.com" (with "appleid" as a valid official subdomain). In option A, the actual domain is "security-id-verification.org", and option D uses a homograph punycode trick.'
    },
    {
      category: 'HTTPS & Padlock Icon Security',
      question: 'Does seeing a padlock icon (HTTPS) in your browser address bar guarantee that a website is safe and trustworthy?',
      options: [
        'Yes, the padlock icon means the website was verified by the FBI and is safe.',
        'Yes, attackers cannot obtain SSL/TLS certificates for phishing websites.',
        'No, HTTPS only encrypts the connection. Anyone, including cybercriminals, can obtain free SSL certificates for phishing sites.',
        'No, the padlock only works on desktop computers, not on mobile smartphones.'
      ],
      correctIndex: 2,
      explanation: 'Crucial Cybersecurity Fact: HTTPS only guarantees encryption between your device and the server hosting the site. Over 85% of phishing websites have valid HTTPS certificates. An encrypted connection to a scammer means your stolen data is transmitted securely to the criminal!'
    },
    {
      category: 'Mobile Smishing Attacks',
      question: 'You receive a text message: "[Post Office]: Package delivery failed due to missing street address. Pay $1.99 redelivery fee at post-delivery-fee.cam". How should you respond?',
      options: [
        'Pay the $1.99 fee immediately because it is a very small amount of money.',
        'Reply to the SMS with your full home address so they can update their records.',
        'Recognize this as a classic Smishing trap, do not click the link, and report/block the sender.',
        'Call the sender number from the SMS and dictate your credit card details over the phone.'
      ],
      correctIndex: 2,
      explanation: 'Postal couriers do not ask for credit card fees via unprompted SMS containing suspicious domains like ".cam". The $1.99 lure is designed to steal your full credit card number and CVV.'
    },
    {
      category: 'Social Engineering & 2FA / OTP',
      question: 'A caller claiming to be from your bank\'s fraud department says: "We detected a fraudulent $900 transfer. I just sent a 6-digit verification code to your phone. Read it to me to cancel the charge." What is happening?',
      options: [
        'The caller is a real bank agent helping you recover your funds.',
        'This is a Vishing attack attempting to intercept your Multi-Factor Authentication (MFA) code to breach your account.',
        'This is a standard procedure required by federal banking regulations.',
        'You should read the code, but only if the caller gives you their badge number.'
      ],
      correctIndex: 1,
      explanation: 'MFA codes are your account security keys! Attackers trigger a real login or password reset, and when your phone receives the real SMS code, they try to trick you into reading it. Official banks explicitly state they will NEVER ask for your one-time code over the phone.'
    },
    {
      category: 'Spear Phishing & Authority Lures',
      question: 'You get an email appearing to come from your company CEO: "I am trapped in an urgent executive meeting. Please buy five $100 Apple gift cards for a client presentation and send me the PINs." What should you do?',
      options: [
        'Buy the gift cards quickly to impress the CEO and get reimbursed later.',
        'Reply with your personal credit card details so the CEO can purchase them directly.',
        'Recognize this as a classic CEO Impersonation (Whaling) scam, do not buy gift cards, and verify with your manager or IT security.',
        'Forward the email to the entire company asking who has spare gift cards.'
      ],
      correctIndex: 2,
      explanation: 'Gift card requests are an unmistakable trademark of social engineering scams. Authentic company leadership will never ask staff to purchase gift cards or share codes over informal email channels.'
    },
    {
      category: 'Dangerous Attachments & Malware',
      question: 'An email from an unfamiliar vendor includes an attachment named "Invoice_Overdue_October2026.pdf.exe". What makes this attachment dangerous?',
      options: [
        'It is an executable program (.exe) disguised with a double extension to trick you into running malware.',
        'It is a PDF file that has too many pages for your computer to open.',
        'Files ending in .exe are always safe because Windows automatically screens them.',
        'There is nothing suspicious about this attachment; it is a normal billing document.'
      ],
      correctIndex: 0,
      explanation: 'Attackers frequently use double extensions (like .pdf.exe or .docx.vbs) hoping victims only notice the ".pdf" and accidentally execute a trojan or ransomware payload.'
    },
    {
      category: 'Typosquatting & Brand Masquerade',
      question: 'What is "Typosquatting" in cybersecurity?',
      options: [
        'A spellcheck software designed to fix typing errors in emails.',
        'The registration of intentionally misspelled domain names (e.g. "amaz0n.com" or "g00gle.com") to deceive users.',
        'A keyboard shortcut used to detect spam messages.',
        'A type of antivirus scan that cleans infected word documents.'
      ],
      correctIndex: 1,
      explanation: 'Typosquatting takes advantage of common typing mistakes or visual similarities (such as using zero "0" for "O", or "rn" for "m") to drive victims to malicious fake portals.'
    },
    {
      category: 'Defensive Best Practices',
      question: 'Why does using a reputable Password Manager provide built-in protection against phishing websites?',
      options: [
        'Password managers automatically shut down suspicious websites worldwide.',
        'Password managers match saved credentials to the exact verified domain, refusing to autofill on lookalike phishing domains.',
        'Password managers send an alert to local police whenever you type a password.',
        'Password managers make all websites require biometric fingerprint scans.'
      ],
      correctIndex: 1,
      explanation: 'Password managers match domains with mathematical accuracy. If you land on "paypa1.com" or "paypal.security-alert.xyz", your password manager knows it is not "paypal.com" and will refuse to autofill your credentials.'
    },
    {
      category: 'Incident Response & Containment',
      question: 'If you accidentally click a suspicious link and enter your workplace password on a fraudulent page, what is the best immediate step?',
      options: [
        'Do nothing and wait a few weeks to see if any money is missing.',
        'Delete the email from your inbox and pretend the incident never happened.',
        'Immediately change your password from a clean device, terminate active sessions, and notify your IT security team.',
        'Turn off your computer monitor so the attacker cannot see your screen.'
      ],
      correctIndex: 2,
      explanation: 'Speed is essential! Quickly resetting your password and notifying IT security allows incident responders to revoke compromised authentication tokens before attackers can pivot deeper into the corporate network.'
    }
  ];

  let currentQuestionIndex = 0;
  let quizScore = 0;
  let hasAnsweredCurrentQuestion = false;

  // DOM Elements for Quiz
  const currentQuestionNumEl = document.getElementById('currentQuestionNum');
  const totalQuestionsNumEl = document.getElementById('totalQuestionsNum');
  const liveScoreEl = document.getElementById('liveScore');
  const quizProgressFill = document.getElementById('quizProgressFill');
  const questionCategoryEl = document.getElementById('questionCategory');
  const questionTitleEl = document.getElementById('questionTitle');
  const quizOptionsGrid = document.getElementById('quizOptionsGrid');
  const quizFeedbackCard = document.getElementById('quizFeedbackCard');
  const feedbackIconEl = document.getElementById('feedbackIcon');
  const feedbackTitleEl = document.getElementById('feedbackTitle');
  const feedbackExplanationEl = document.getElementById('feedbackExplanation');
  const nextQuestionBtn = document.getElementById('nextQuestionBtn');
  const quizInteractiveArea = document.getElementById('quizInteractiveArea');
  const quizResultsCard = document.getElementById('quizResultsCard');
  const quizMetaHeader = document.getElementById('quizMetaHeader');
  const restartQuizBtn = document.getElementById('restartQuizBtn');

  // Results elements
  const scorePercentageEl = document.getElementById('scorePercentage');
  const scoreFractionEl = document.getElementById('scoreFraction');
  const resultsRankEl = document.getElementById('resultsRank');
  const resultsNarrativeEl = document.getElementById('resultsNarrative');

  // Certificate elements
  const certNameInput = document.getElementById('certNameInput');
  const generateCertBtn = document.getElementById('generateCertBtn');
  const certModalBackdrop = document.getElementById('certModalBackdrop');
  const closeCertBtn = document.getElementById('closeCertBtn');
  const certRecipientName = document.getElementById('certRecipientName');
  const certIssueDate = document.getElementById('certIssueDate');
  const printCertBtn = document.getElementById('printCertBtn');

  function initQuiz() {
    currentQuestionIndex = 0;
    quizScore = 0;
    hasAnsweredCurrentQuestion = false;

    if (totalQuestionsNumEl) {
      totalQuestionsNumEl.textContent = quizQuestions.length;
    }

    quizResultsCard.classList.add('hidden');
    quizInteractiveArea.classList.remove('hidden');
    quizMetaHeader.classList.remove('hidden');

    renderQuestion();
  }

  function renderQuestion() {
    hasAnsweredCurrentQuestion = false;
    const q = quizQuestions[currentQuestionIndex];

    // Meta updates
    currentQuestionNumEl.textContent = currentQuestionIndex + 1;
    liveScoreEl.textContent = quizScore;
    const progressPercent = ((currentQuestionIndex) / quizQuestions.length) * 100;
    quizProgressFill.style.width = `${progressPercent}%`;

    // Question content
    questionCategoryEl.textContent = `Category: ${q.category}`;
    questionTitleEl.textContent = q.question;

    // Reset feedback card
    quizFeedbackCard.classList.add('hidden');
    quizFeedbackCard.className = 'quiz-feedback-card hidden';

    // Render Options
    const letters = ['A', 'B', 'C', 'D'];
    quizOptionsGrid.innerHTML = '';

    q.options.forEach((optText, idx) => {
      const btn = document.createElement('button');
      btn.className = 'quiz-option-btn';
      btn.setAttribute('type', 'button');
      btn.innerHTML = `
        <span class="option-badge">${letters[idx]}</span>
        <span class="option-text">${optText}</span>
      `;
      btn.addEventListener('click', () => handleOptionSelect(idx));
      quizOptionsGrid.appendChild(btn);
    });
  }

  function handleOptionSelect(selectedIndex) {
    if (hasAnsweredCurrentQuestion) return;
    hasAnsweredCurrentQuestion = true;

    const q = quizQuestions[currentQuestionIndex];
    const isCorrect = selectedIndex === q.correctIndex;
    const allOptionButtons = quizOptionsGrid.querySelectorAll('.quiz-option-btn');

    // Disable all options
    allOptionButtons.forEach((btn, idx) => {
      btn.disabled = true;
      if (idx === q.correctIndex) {
        btn.classList.add('correct');
      } else if (idx === selectedIndex && !isCorrect) {
        btn.classList.add('incorrect');
      }
    });

    if (isCorrect) {
      quizScore += 1;
      liveScoreEl.textContent = quizScore;
      quizFeedbackCard.className = 'quiz-feedback-card is-correct';
      feedbackIconEl.textContent = '✅';
      feedbackTitleEl.textContent = 'Correct Answer!';
    } else {
      quizFeedbackCard.className = 'quiz-feedback-card is-incorrect';
      feedbackIconEl.textContent = '❌';
      feedbackTitleEl.textContent = 'Incorrect Choice';
    }

    feedbackExplanationEl.textContent = q.explanation;
    quizFeedbackCard.classList.remove('hidden');

    // If it was the last question, change next button text
    if (currentQuestionIndex === quizQuestions.length - 1) {
      nextQuestionBtn.querySelector('span').textContent = 'View Final Results';
    } else {
      nextQuestionBtn.querySelector('span').textContent = 'Next Question';
    }
  }

  nextQuestionBtn.addEventListener('click', () => {
    if (currentQuestionIndex < quizQuestions.length - 1) {
      currentQuestionIndex += 1;
      renderQuestion();
    } else {
      showQuizResults();
    }
  });

  function showQuizResults() {
    quizInteractiveArea.classList.add('hidden');
    quizMetaHeader.classList.add('hidden');
    quizResultsCard.classList.remove('hidden');

    const total = quizQuestions.length;
    const percentage = Math.round((quizScore / total) * 100);

    scorePercentageEl.textContent = `${percentage}%`;
    scoreFractionEl.textContent = `${quizScore} out of ${total} Questions Correct`;

    let rank = '';
    let narrative = '';

    if (percentage >= 90) {
      rank = 'Cyber Defense Sentinel (Elite Master)';
      narrative = 'Sensational mastery! You have demonstrated exceptional digital defense reflexes. You can spot spoofed headers, decipher deceptive URLs, neutralize social engineering coercion, and protect your identity with precision.';
    } else if (percentage >= 70) {
      rank = 'Security Guardian (Proficient)';
      narrative = 'Great achievement! You have solid awareness of phishing tactics and domain structures. Review the questions you missed to sharpen your instincts even further.';
    } else if (percentage >= 50) {
      rank = 'Cyber Apprentice (Developing)';
      narrative = 'Good effort! You understand foundational security concepts, but attackers could still catch you with subtle lures or urgent psychological pressure. We recommend reviewing the simulated examples!';
    } else {
      rank = 'High Vulnerability (Needs Reinforcement)';
      narrative = 'Careful attention needed! Phishing techniques frequently exploited your selections. Spend some time reviewing our "Learn" and "Fake Sites" sections and restart the quiz to master these vital defenses.';
    }

    resultsRankEl.textContent = rank;
    resultsNarrativeEl.textContent = narrative;

    // Scroll to results card
    quizResultsCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  // Restart Quiz
  if (restartQuizBtn) {
    restartQuizBtn.addEventListener('click', () => {
      initQuiz();
    });
  }

  // Certificate Generation
  if (generateCertBtn && certModalBackdrop) {
    generateCertBtn.addEventListener('click', () => {
      const userName = certNameInput.value.trim() || 'Cyber Defender';
      certRecipientName.textContent = userName;

      const now = new Date();
      const options = { year: 'numeric', month: 'long', day: 'numeric' };
      certIssueDate.textContent = `Issued: ${now.toLocaleDateString(undefined, options)}`;

      certModalBackdrop.classList.remove('hidden');
    });

    closeCertBtn.addEventListener('click', () => {
      certModalBackdrop.classList.add('hidden');
    });

    certModalBackdrop.addEventListener('click', (e) => {
      if (e.target === certModalBackdrop) {
        certModalBackdrop.classList.add('hidden');
      }
    });

    printCertBtn.addEventListener('click', () => {
      window.print();
    });
  }

  // Initialize Quiz
  initQuiz();

  /* ==========================================================================
     6. FINAL SAFETY PRE-CLICK CHECKLIST
     ========================================================================== */
  const checklistBoxes = document.querySelectorAll('.checklist-checkbox');
  const checklistPercentEl = document.getElementById('checklistPercent');
  const checklistStatusText = document.getElementById('checklistStatusText');
  const checklistProgressFill = document.getElementById('checklistProgressFill');
  const resetChecklistBtn = document.getElementById('resetChecklistBtn');
  const checklistVerdictBanner = document.getElementById('checklistVerdictBanner');
  const chkVerdictHeader = document.getElementById('chkVerdictHeader');
  const chkVerdictDetail = document.getElementById('chkVerdictDetail');

  function updateChecklist() {
    const total = checklistBoxes.length;
    let checkedCount = 0;

    checklistBoxes.forEach(chk => {
      if (chk.checked) checkedCount++;
    });

    const percent = Math.round((checkedCount / total) * 100);
    checklistPercentEl.textContent = `${percent}%`;
    checklistProgressFill.style.width = `${percent}%`;

    if (percent === 100) {
      checklistStatusText.className = 'badge-success';
      checklistStatusText.textContent = 'Fully Verified — Safe to Proceed';
      checklistVerdictBanner.className = 'checklist-verdict-banner all-checked';
      chkVerdictHeader.textContent = 'All Security Checks Satisfied!';
      chkVerdictDetail.textContent = 'You have verified the sender domain, inspected the real URL, checked for urgency pressure, and confirmed that secrets are protected. Safe to proceed.';
    } else if (percent >= 50) {
      checklistStatusText.className = 'badge-warning';
      checklistStatusText.textContent = 'Caution: Incomplete Verification';
      checklistVerdictBanner.className = 'checklist-verdict-banner';
      chkVerdictHeader.textContent = 'Partial Verification Complete';
      chkVerdictDetail.textContent = 'Do not click links or provide credentials until all remaining items are thoroughly verified.';
    } else {
      checklistStatusText.className = 'badge-neutral';
      checklistStatusText.textContent = 'Review Checklist Items';
      checklistVerdictBanner.className = 'checklist-verdict-banner';
      chkVerdictHeader.textContent = 'Safety Check in Progress';
      chkVerdictDetail.textContent = 'Select each verified item above to confirm you are safe to proceed.';
    }
  }

  checklistBoxes.forEach(chk => {
    chk.addEventListener('change', updateChecklist);
  });

  if (resetChecklistBtn) {
    resetChecklistBtn.addEventListener('click', () => {
      checklistBoxes.forEach(chk => {
        chk.checked = false;
      });
      updateChecklist();
    });
  }

  /* ==========================================================================
     7. GLOSSARY REAL-TIME SEARCH FILTER
     ========================================================================== */
  const glossarySearchInput = document.getElementById('glossarySearchInput');
  const glossaryCards = document.querySelectorAll('.glossary-card');

  if (glossarySearchInput) {
    glossarySearchInput.addEventListener('input', () => {
      const query = glossarySearchInput.value.toLowerCase().trim();

      glossaryCards.forEach(card => {
        const title = card.querySelector('h4').textContent.toLowerCase();
        const desc = card.querySelector('p').textContent.toLowerCase();
        const termData = card.getAttribute('data-term') || '';

        if (title.includes(query) || desc.includes(query) || termData.includes(query)) {
          card.classList.remove('hidden');
        } else {
          card.classList.add('hidden');
        }
      });
    });
  }
});
