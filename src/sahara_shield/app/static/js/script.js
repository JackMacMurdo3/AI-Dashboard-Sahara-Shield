const btn = document.getElementById('find-malware-btn');
const systemStatus = document.getElementById('system-status');
const logFeed = document.getElementById('log-feed');
const gaugeFill = document.getElementById('gauge-fill');
const gaugeValue = document.getElementById('gauge-value');
const confidenceLabel = document.getElementById('confidence-label');
const scanProgressWrap = document.getElementById('scan-progress-wrap');
const scanProgressFill = document.getElementById('scan-progress-fill');
const scanProgressLabel = document.getElementById('scan-progress-label');
const activeScanInfo = document.getElementById('active-scan-info');
const inferenceTimer = document.getElementById('inference-timer');

// Pipeline stage elements
const stages = {
  ingest:    document.getElementById('stage-ingest'),
  static:    document.getElementById('stage-static'),
  inference: document.getElementById('stage-inference'),
  classify:  document.getElementById('stage-classify'),
  report:    document.getElementById('stage-report'),
};

// Simulated scan targets
const scanTargets = [
  { name: 'suspicious_loader.js', size: '14 KB', lang: 'JavaScript' },
  { name: 'update_patch.exe',     size: '82 KB', lang: 'Binary'     },
  { name: 'monitor_svc.py',       size: '6 KB',  lang: 'Python'     },
  { name: 'config_hook.sh',       size: '3 KB',  lang: 'Shell'      },
];

function addLog(level, msg) {
  const now = new Date();
  const ts = now.toTimeString().slice(0, 8);

  const line = document.createElement('div');
  line.className = 'log-line';

  const tsSpan = document.createElement('span');
  tsSpan.className = 'log-ts';
  tsSpan.textContent = ts;

  const levelSpan = document.createElement('span');
  levelSpan.className = 'log-' + level;
  levelSpan.textContent = '[' + level.toUpperCase() + ']';

  const msgSpan = document.createElement('span');
  msgSpan.className = 'log-msg';
  msgSpan.textContent = msg;

  line.appendChild(tsSpan);
  line.appendChild(levelSpan);
  line.appendChild(msgSpan);
  logFeed.appendChild(line);
  logFeed.scrollTop = logFeed.scrollHeight;
}

function setStage(name, state, time) {
  const el = stages[name];
  el.className = 'stage ' + state;
  const statusEl = el.querySelector('.stage-status');
  const timeEl = el.querySelector('.stage-time');
  if (state === 'running')  statusEl.textContent = 'Running...';
  if (state === 'done')     statusEl.textContent = 'Complete';
  if (state === 'waiting')  statusEl.textContent = 'Idle';
  if (state === 'error')    statusEl.textContent = 'Error';
  timeEl.textContent = time || '—';
}

function resetPipeline() {
  Object.keys(stages).forEach(s => setStage(s, 'waiting', '—'));
  inferenceTimer.textContent = '—';
}

function setProgress(pct) {
  scanProgressFill.style.width = pct + '%';
  scanProgressLabel.textContent = pct + '%';
}

function setGauge(pct) {
  const arcLen = 157;
  const filled = (pct / 100) * arcLen;
  gaugeFill.setAttribute('stroke-dasharray', filled + ' ' + arcLen);
  gaugeValue.textContent = pct + '%';

  if (pct >= 90) {
    gaugeFill.style.stroke = 'var(--error)';
    confidenceLabel.textContent = 'High confidence — likely malware';
  } else if (pct >= 70) {
    gaugeFill.style.stroke = 'var(--warn)';
    confidenceLabel.textContent = 'Moderate confidence — suspicious';
  } else {
    gaugeFill.style.stroke = 'var(--lime)';
    confidenceLabel.textContent = 'Low confidence — probably clean';
  }
}

function runScan() {
  btn.disabled = true;
  systemStatus.textContent = 'SCANNING';
  resetPipeline();

  const target = scanTargets[Math.floor(Math.random() * scanTargets.length)];

  activeScanInfo.innerHTML =
    '<div class="scan-file-name">' + target.name + '</div>' +
    '<div class="scan-meta">' + target.size + ' &nbsp;·&nbsp; ' + target.lang + '</div>';

  scanProgressWrap.hidden = false;
  setProgress(0);

  addLog('info', 'Scan started: ' + target.name);

  // Stage 1 — File Ingestion
  setStage('ingest', 'running');
  addLog('info', 'Ingesting file: ' + target.name + ' (' + target.size + ')');

  let progressInterval = setInterval(() => {
    const fill = scanProgressFill;
    const current = parseFloat(fill.style.width) || 0;
    if (current < 20) setProgress(Math.min(current + 2, 20));
  }, 80);

  setTimeout(() => {
    setStage('ingest', 'done', '0.3s');
    addLog('info', 'File ingestion complete');

    // Stage 2 — Static Analysis
    setStage('static', 'running');
    addLog('info', 'Running static analysis...');

    setTimeout(() => {
      clearInterval(progressInterval);
      setProgress(40);
      setStage('static', 'done', '0.6s');
      addLog('warn', 'Suspicious import patterns detected');

      // Stage 3 — AI Inference
      setStage('inference', 'running');
      addLog('info', 'AI model inference started');

      const inferenceStart = Date.now();
      const timerHandle = setInterval(() => {
        const elapsed = ((Date.now() - inferenceStart) / 1000).toFixed(1);
        inferenceTimer.textContent = elapsed + 's';
        const p = 40 + Math.min(((Date.now() - inferenceStart) / 2000) * 30, 30);
        setProgress(Math.round(p));
      }, 100);

      setTimeout(() => {
        clearInterval(timerHandle);
        const elapsed = ((Date.now() - inferenceStart) / 1000).toFixed(1);
        setStage('inference', 'done', elapsed + 's');
        setProgress(70);
        addLog('info', 'Inference complete in ' + elapsed + 's');

        // Stage 4 — Classification
        setStage('classify', 'running');
        addLog('info', 'Classifying threat...');

        setTimeout(() => {
          setStage('classify', 'done', '0.2s');
          setProgress(90);

          const confidence = Math.floor(Math.random() * 30) + 70;
          setGauge(confidence);
          addLog('info', 'Classification confidence: ' + confidence + '%');

          // Stage 5 — Report
          setStage('report', 'running');
          addLog('info', 'Generating report...');

          setTimeout(() => {
            setStage('report', 'done', '0.1s');
            setProgress(100);
            addLog('info', 'Scan complete: ' + target.name);

            systemStatus.textContent = 'IDLE';
            btn.disabled = false;

            addRecentScan(target.name, confidence >= 70 ? 'threat' : 'clean');
          }, 600);
        }, 800);
      }, 2500);
    }, 900);
  }, 700);
}

function addRecentScan(filename, result) {
  const tbody = document.getElementById('recent-table-body');
  const now = new Date().toTimeString().slice(0, 8);
  const duration = (Math.random() * 1.5 + 0.8).toFixed(1) + 's';

  const row = document.createElement('tr');

  const tdTime = document.createElement('td');
  tdTime.className = 'muted';
  tdTime.textContent = now;

  const tdFile = document.createElement('td');
  tdFile.textContent = filename;

  const tdResult = document.createElement('td');
  const badge = document.createElement('span');
  badge.className = 'result ' + result;
  badge.textContent = result === 'threat' ? 'Threat' : 'Clean';
  tdResult.appendChild(badge);

  const tdDuration = document.createElement('td');
  tdDuration.className = 'muted';
  tdDuration.textContent = duration;

  row.appendChild(tdTime);
  row.appendChild(tdFile);
  row.appendChild(tdResult);
  row.appendChild(tdDuration);

  tbody.insertBefore(row, tbody.firstChild);
}

btn.addEventListener('click', runScan);
