let svg, g, zoom;
let _graphData     = null;
let _allNodes      = [];
let _categories    = [];
let _workspaceSlug = null;
let _dataUrl       = null;

// Layout constants
const LABEL_W   = 28;    // left lane label column — narrow, labels are vertical
const NODE_W    = 200;
const NODE_H    = 90;
const NODE_RX   = 8;
const TAG_H     = 28;
const COL_GAP   = 8;
const ROW_PAD   = 40;    // vertical padding inside each lane
const IP_PAD    = 8;     // top padding above node (no floating label)
const LANE_GAP  = 0;     // gap between lanes (0 = just the divider line)
const SIDE_PAD  = 6;

// Port pill constants
const PORT_PILL_W   = 34;   // fixed pill width (fits up to 5-digit ports)
const PORT_PILL_H   = 15;   // pill height
const PORT_PILL_GAP = 3;    // horizontal gap between pills
const PORT_ROW_GAP  = 4;    // vertical gap between port rows
const PORT_PAD_TOP  = 7;    // space between node bottom and first port row
const MAX_PORT_ROWS = 3;    // maximum rows of ports to display

// Colors
const NODE_FILL     = '#f77f00';
const NODE_STROKE   = '#c96300';
const TEXT_PRIMARY  = '#ffffff';
const TEXT_DIM      = 'rgba(255,255,255,0.55)';
const IP_COLOR      = '#adb5bd';
const TAG_COLOR     = '#ffe08a';
const LANE_BG       = 'rgba(255,255,255,0.025)';
const LANE_LINE     = 'rgba(0,210,255,0.2)';
const LABEL_COLOR   = 'rgba(0,210,255,0.7)';
const UNCAT_LABEL   = 'rgba(255,255,255,0.25)';

// ── Init ──────────────────────────────────────────────────────────────────

function initNetworkGraph(dataUrl, workspaceSlug) {
  _dataUrl       = dataUrl;
  _workspaceSlug = workspaceSlug;

  svg = d3.select('#networkGraph');

  // Zoom used only for programmatic transforms; all user interaction disabled
  zoom = d3.zoom()
    .filter(() => false)
    .on('zoom', e => g.attr('transform', e.transform));
  svg.call(zoom);

  // Hacker grid background
  const defs = svg.append('defs');
  const pat = defs.append('pattern')
    .attr('id', 'hackerGrid').attr('width', 40).attr('height', 40)
    .attr('patternUnits', 'userSpaceOnUse');
  pat.append('path')
    .attr('d', 'M 40 0 L 0 0 0 40').attr('fill', 'none')
    .attr('stroke', 'rgba(0,210,255,0.12)').attr('stroke-width', '0.8');
  pat.append('circle').attr('cx', 0).attr('cy', 0).attr('r', 1.2)
    .attr('fill', 'rgba(0,210,255,0.25)');
  svg.insert('rect', ':first-child')
    .attr('width', '100%').attr('height', '100%').attr('fill', '#040e1a');
  svg.insert('rect', ':nth-child(2)')
    .attr('width', '100%').attr('height', '100%').attr('fill', 'url(#hackerGrid)');

  g = svg.append('g');

  const ro = new ResizeObserver(() => {
    if (_allNodes.length) reflowAndFit(false);
  });
  ro.observe(svg.node().parentElement);

  loadGraph();
}

// ── Load ──────────────────────────────────────────────────────────────────

function loadGraph() {
  document.getElementById('graph-loading').style.display = 'flex';
  fetch(_dataUrl)
    .then(r => r.json())
    .then(data => {
      _graphData  = data;
      // Active nodes first so they occupy top rows in each lane; ghosts follow
      _allNodes   = [
        ...data.nodes.filter(n => !n.ghost),
        ...data.nodes.filter(n =>  n.ghost),
      ];
      _categories = data.categories || [];
      document.getElementById('graph-loading').style.display = 'none';
      g.selectAll('*').remove();
      renderGraph();
    })
    .catch(() => {
      document.getElementById('graph-loading').innerHTML =
        '<p class="text-danger">Failed to load graph data</p>';
    });
}

// ── Layout ────────────────────────────────────────────────────────────────

function svgWidth()  { return svg.node().clientWidth  || 900; }
function svgHeight() { return svg.node().clientHeight || 600; }

function colsInLane() {
  const usable = svgWidth() - LABEL_W - SIDE_PAD * 2;
  return Math.max(1, Math.floor((usable + COL_GAP) / (NODE_W + COL_GAP)));
}

function nodeWidth() {
  const cols   = colsInLane();
  const usable = svgWidth() - LABEL_W - SIDE_PAD * 2;
  return Math.floor((usable - COL_GAP * (cols - 1)) / cols);
}

// How many port pills fit in one row for the given node width
function pillsPerRow(nw) {
  return Math.max(1, Math.floor((nw + PORT_PILL_GAP) / (PORT_PILL_W + PORT_PILL_GAP)));
}

// Total height a node occupies including its port pills area
function nodeEffectiveH(node, nw) {
  if (!node.ports || !node.ports.length) return NODE_H;
  const rows = Math.min(MAX_PORT_ROWS, Math.ceil(node.ports.length / pillsPerRow(nw)));
  return NODE_H + PORT_PAD_TOP + rows * (PORT_PILL_H + PORT_ROW_GAP);
}

function assignPositions(nodes) {
  const cols    = colsInLane();
  const nw      = nodeWidth();
  const colStep = nw + COL_GAP;
  const nodeX0  = LABEL_W + SIDE_PAD;

  // Group by category (null = uncategorized)
  const catMap = new Map();
  for (const cat of _categories) catMap.set(cat.id, []);
  catMap.set(null, []);

  for (const n of nodes) {
    const key = n.category_id ?? null;
    if (!catMap.has(key)) catMap.set(key, []);
    catMap.get(key).push(n);
  }

  let currentY = 0;

  for (const [catId, group] of catMap) {
    if (!group.length) continue;

    const numRows = Math.ceil(group.length / cols);
    let rowY      = currentY + ROW_PAD + IP_PAD;
    let laneInner = IP_PAD;

    for (let row = 0; row < numRows; row++) {
      const rowNodes = group.slice(row * cols, (row + 1) * cols);
      // Lane row height = tallest effective node in that row
      const rowH = Math.max(...rowNodes.map(n => nodeEffectiveH(n, nw)));

      rowNodes.forEach((n, col) => {
        n._x     = nodeX0 + col * colStep;
        n._y     = rowY;
        n._laneY = currentY;
        n._catId = catId;
        n._nw    = nw;
      });

      rowY       += rowH + COL_GAP;
      laneInner  += rowH + (row < numRows - 1 ? COL_GAP : 0);
    }

    const laneH = laneInner + ROW_PAD * 2;
    group.forEach(n => n._laneH = laneH);
    currentY += laneH + LANE_GAP;
  }

  return { catMap, totalH: currentY };
}

function reflowAndFit(animate = true) {
  const { catMap, totalH } = assignPositions(_allNodes);
  const dur = animate ? 500 : 0;

  // Move nodes and update their widths (node width changes with viewport)
  g.selectAll('.node')
    .data(_allNodes, d => d.ip)
    .transition().duration(dur)
    .attr('transform', d => `translate(${d._x},${d._y})`)
    .each(function(d) {
      const sel = d3.select(this);
      sel.select('rect.node-body').attr('width', d._nw);
      sel.selectAll('rect').filter(function() { return !this.classList.contains('node-body'); }).attr('width', d._nw);
      sel.selectAll('text').each(function() {
        const t = d3.select(this);
        if (t.attr('text-anchor') === 'middle') t.attr('x', d._nw / 2);
      });
      // Port pills depend on node width — remove and re-render
      sel.select('.port-pills').remove();
      renderPortPills(sel, d);
    });

  // Update lanes
  renderLanes(catMap, totalH, dur);
  fitAll(dur);
}

// ── Render ────────────────────────────────────────────────────────────────

function renderGraph() {
  const { catMap, totalH } = assignPositions(_allNodes);

  renderLanes(catMap, totalH, 0);

  // Nodes
  const nodeGroup = g.selectAll('.node')
    .data(_allNodes, d => d.ip)
    .enter().append('g')
    .attr('class', 'node')
    .attr('transform', d => `translate(${d._x},${d._y})`)
    .style('cursor', 'pointer')
    .on('click', (event, d) => {
      event.stopPropagation();
      // Reset active nodes to solid stroke, ghost nodes to dashed stroke
      g.selectAll('.node rect.node-body').each(function(nd) {
        const defaultStroke = nd.ghost
          ? (nd.category_color ? d3.color(nd.category_color).darker(0.3).formatHex() : '#555')
          : (nd.category_color ? d3.color(nd.category_color).darker(0.6).formatHex() : NODE_STROKE);
        d3.select(this).attr('stroke', defaultStroke).attr('stroke-width', nd.ghost ? 1.5 : 1.5);
      });
      d3.select(event.currentTarget).select('rect.node-body')
        .attr('stroke', '#fff').attr('stroke-width', 2.5);
      showHostDetail(d);
    });

  // Ghost nodes — faded, dashed, no edits from sidebar
  nodeGroup.filter(d => d.ghost).attr('opacity', 0.42);

  // Body rect — category color when assigned, fallback to default orange
  nodeGroup.append('rect')
    .attr('class', 'node-body')
    .attr('width', d => d._nw).attr('height', NODE_H).attr('rx', NODE_RX)
    .attr('fill', d => {
      if (d.ghost) return d.category_color
        ? d3.color(d.category_color).darker(1.8).formatHex()
        : '#111820';
      return d.category_color || NODE_FILL;
    })
    .attr('stroke', d => d.ghost
      ? (d.category_color ? d3.color(d.category_color).darker(0.3).formatHex() : '#555')
      : (d.category_color ? d3.color(d.category_color).darker(0.6).formatHex() : NODE_STROKE))
    .attr('stroke-width', 1.5)
    .attr('stroke-dasharray', d => d.ghost ? '5 3' : null);

  // Tag strip (all nodes; ghost nodes get a dimmer strip, and only if they have a tag)
  nodeGroup.filter(d => !d.ghost || d.tag).append('rect')
    .attr('x', 0).attr('y', NODE_H - TAG_H)
    .attr('width', d => d._nw).attr('height', TAG_H).attr('rx', NODE_RX)
    .attr('fill', d => d.ghost ? 'rgba(0,0,0,0.15)' : 'rgba(0,0,0,0.25)');

  // Tag text (active nodes always; ghost nodes only if they have a tag)
  nodeGroup.filter(d => !d.ghost || d.tag).append('text')
    .attr('class', 'tag-text')
    .attr('x', d => d._nw / 2).attr('y', NODE_H - TAG_H / 2 + 1)
    .attr('text-anchor', 'middle').attr('dominant-baseline', 'middle')
    .attr('font-size', '11px')
    .attr('font-style', 'normal')
    .attr('fill', d => d.ghost ? 'rgba(255,255,255,0.45)' : (d.tag ? TAG_COLOR : 'rgba(255,255,255,0.25)'))
    .text(d => d.tag || (d.ghost ? '' : 'add tag…'));

  // Red offline dot at top-right corner for ghost nodes
  nodeGroup.filter(d => d.ghost)
    .append('circle')
    .attr('cx', d => d._nw - 9).attr('cy', 9)
    .attr('r', 5)
    .attr('fill', '#dc3545')
    .attr('stroke', 'rgba(0,0,0,0.4)').attr('stroke-width', 1);

  // Orange shuffle dot at top-left for randomized-MAC nodes
  nodeGroup.filter(d => d.randomized_mac)
    .append('circle')
    .attr('cx', 9).attr('cy', 9)
    .attr('r', 5)
    .attr('fill', '#ffa94d')
    .attr('stroke', 'rgba(0,0,0,0.4)').attr('stroke-width', 1);

  // Port pills below each node
  nodeGroup.each(function(d) { renderPortPills(d3.select(this), d); });

  // Primary label (hostname / vendor / ip fallback)
  nodeGroup.append('text')
    .attr('x', d => d._nw / 2).attr('y', (NODE_H - TAG_H) / 2 - 12)
    .attr('text-anchor', 'middle').attr('dominant-baseline', 'middle')
    .attr('font-size', '13px').attr('font-weight', '700').attr('fill', TEXT_PRIMARY)
    .text(d => trunc(d.hostname || d.vendor || d.ip, 20));

  // IP address inside box
  nodeGroup.append('text')
    .attr('x', d => d._nw / 2).attr('y', (NODE_H - TAG_H) / 2 + 14)
    .attr('text-anchor', 'middle').attr('dominant-baseline', 'middle')
    .attr('font-size', '15px').attr('fill', 'rgba(255,255,255,0.75)').attr('font-family', 'monospace')
    .text(d => d.ip);


  svg.on('click', () => {
    g.selectAll('.node rect.node-body').each(function(nd) {
      const defaultStroke = nd.ghost
        ? (nd.category_color ? d3.color(nd.category_color).darker(0.3).formatHex() : '#555')
        : (nd.category_color ? d3.color(nd.category_color).darker(0.6).formatHex() : NODE_STROKE);
      d3.select(this).attr('stroke', defaultStroke).attr('stroke-width', 1.5);
    });
    showDefaultSidebar();
  });

  fitAll(0);
}

function renderPortPills(sel, d) {
  if (!d.ports || !d.ports.length) return;

  const nw    = d._nw;
  const ppr   = pillsPerRow(nw);
  const max   = MAX_PORT_ROWS * ppr;
  const shown = d.ports.length > max ? d.ports.slice(0, max - 1) : d.ports;
  const extra = d.ports.length - shown.length;
  const items = extra > 0 ? [...shown, { portid: null, _overflow: extra }] : shown;

  const portG = sel.append('g')
    .attr('class', 'port-pills')
    .attr('transform', `translate(0,${NODE_H + PORT_PAD_TOP})`);

  items.forEach((p, i) => {
    const col = i % ppr;
    const row = Math.floor(i / ppr);
    const px  = col * (PORT_PILL_W + PORT_PILL_GAP);
    const py  = row * (PORT_PILL_H + PORT_ROW_GAP);
    const ov  = !!p._overflow;

    const pill = portG.append('g').attr('transform', `translate(${px},${py})`);
    pill.append('rect')
      .attr('width', PORT_PILL_W).attr('height', PORT_PILL_H).attr('rx', 3)
      .attr('fill', ov ? 'rgba(255,255,255,0.05)' : 'rgba(0,210,255,0.1)')
      .attr('stroke', ov ? 'rgba(255,255,255,0.2)' : 'rgba(0,210,255,0.35)')
      .attr('stroke-width', 0.5);
    pill.append('text')
      .attr('x', PORT_PILL_W / 2).attr('y', PORT_PILL_H / 2 + 1)
      .attr('text-anchor', 'middle').attr('dominant-baseline', 'middle')
      .attr('font-size', '9px')
      .attr('fill', d.ghost
        ? (ov ? 'rgba(255,255,255,0.25)' : 'rgba(0,210,255,0.35)')
        : (ov ? 'rgba(255,255,255,0.55)' : 'rgba(0,210,255,0.85)'))
      .text(ov ? `+${p._overflow}` : p.portid);
  });
}

function renderLanes(catMap, totalH, dur = 0) {
  const w        = Math.max(svgWidth() * 2, 1400);
  const ACCENT_W = 4;

  g.selectAll('.lane').remove();
  const laneG = g.insert('g', ':first-child').attr('class', 'lane');

  for (const [catId, group] of catMap) {
    if (!group.length) continue;
    const laneY = group[0]._laneY;
    const laneH = group[0]._laneH;
    const cat   = _categories.find(c => c.id === catId);
    const label = cat ? cat.name : 'Uncategorized';
    const color = cat ? cat.color : 'rgba(255,255,255,0.15)';

    // Lane background
    laneG.append('rect')
      .attr('x', 0).attr('y', laneY)
      .attr('width', w).attr('height', laneH)
      .attr('fill', LANE_BG);

    // Top separator line
    laneG.append('line')
      .attr('x1', 0).attr('y1', laneY)
      .attr('x2', w).attr('y2', laneY)
      .attr('stroke', LANE_LINE).attr('stroke-width', 1);

    // Vertical divider between label column and nodes
    laneG.append('line')
      .attr('x1', LABEL_W).attr('y1', laneY)
      .attr('x2', LABEL_W).attr('y2', laneY + laneH)
      .attr('stroke', LANE_LINE).attr('stroke-width', 1);

    // Category color accent on left edge
    laneG.append('rect')
      .attr('x', 0).attr('y', laneY)
      .attr('width', ACCENT_W).attr('height', laneH)
      .attr('fill', color);

    // Category label — rotated 90° to fit in the narrow label column
    laneG.append('text')
      .attr('class', cat ? 'drag-handle' : '')
      .attr('transform', `translate(${LABEL_W / 2},${laneY + laneH / 2}) rotate(-90)`)
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'middle')
      .attr('font-size', '13px')
      .attr('font-weight', cat ? '700' : '400')
      .attr('fill', cat ? LABEL_COLOR : UNCAT_LABEL)
      .attr('letter-spacing', '0.06em')
      .attr('data-cat-id', catId)
      .style('cursor', cat ? 'grab' : 'default')
      .text(label.toUpperCase());
  }

  // Bottom border
  laneG.append('line')
    .attr('x1', 0).attr('y1', totalH)
    .attr('x2', w).attr('y2', totalH)
    .attr('stroke', LANE_LINE).attr('stroke-width', 1);

  // Attach drag-to-reorder on the lane label area
  attachLaneDrag(catMap, totalH);
}

// ── Lane drag-to-reorder ──────────────────────────────────────────────────

function attachLaneDrag(catMap, totalH) {
  // Build ordered list of real categories that are currently visible
  const visible = _categories.filter(c => catMap.has(c.id) && (catMap.get(c.id) || []).length > 0);
  if (visible.length < 2) return;

  // Map catId → laneY + laneH for hit-testing
  const laneRects = new Map();
  for (const [catId, group] of catMap) {
    if (!group.length) continue;
    laneRects.set(catId, { y: group[0]._laneY, h: group[0]._laneH });
  }

  let _dragCatId   = null;
  let _dragStartY  = 0;
  let _dragGhost   = null;
  let _dragOverlay = null;
  let _currentTransform = d3.zoomTransform(svg.node());

  const drag = d3.drag()
    .filter(event => {
      // Only activate drag on the label column area (x < LABEL_W in graph coords)
      const t = d3.zoomTransform(svg.node());
      const gx = (event.x - t.x) / t.k;
      return gx < LABEL_W;
    })
    .on('start', function(event) {
      _currentTransform = d3.zoomTransform(svg.node());
      const gy = (event.y - _currentTransform.y) / _currentTransform.k;

      // Find which lane was clicked
      _dragCatId = null;
      for (const [catId, rect] of laneRects) {
        if (_categories.find(c => c.id === catId) && gy >= rect.y && gy < rect.y + rect.h) {
          _dragCatId = catId;
          break;
        }
      }
      if (_dragCatId === null) return;

      _dragStartY = event.y;
      svg.style('cursor', 'grabbing');

      // Ghost indicator line
      _dragGhost = g.append('rect')
        .attr('class', 'drag-ghost')
        .attr('x', 0)
        .attr('y', laneRects.get(_dragCatId).y)
        .attr('width', LABEL_W)
        .attr('height', laneRects.get(_dragCatId).h)
        .attr('fill', 'rgba(0,210,255,0.08)')
        .attr('stroke', 'rgba(0,210,255,0.6)')
        .attr('stroke-width', 1.5)
        .attr('stroke-dasharray', '4 3')
        .attr('pointer-events', 'none');

      // Suppress pan during drag
      svg.on('.zoom', null);
    })
    .on('drag', function(event) {
      if (_dragCatId === null) return;
      const dy = event.y - _dragStartY;
      const t  = _currentTransform;
      _dragGhost.attr('y', laneRects.get(_dragCatId).y + dy / t.k);

      // Highlight drop target
      const gyCurrent = (event.y - t.y) / t.k;
      g.selectAll('.lane-drop-indicator').remove();
      for (const [catId, rect] of laneRects) {
        if (catId === _dragCatId) continue;
        if (!_categories.find(c => c.id === catId)) continue;
        if (gyCurrent >= rect.y && gyCurrent < rect.y + rect.h) {
          g.insert('line', '.node')
            .attr('class', 'lane-drop-indicator')
            .attr('x1', 0).attr('x2', LABEL_W)
            .attr('y1', rect.y).attr('y2', rect.y)
            .attr('stroke', 'rgba(0,210,255,0.9)').attr('stroke-width', 2)
            .attr('pointer-events', 'none');
          break;
        }
      }
    })
    .on('end', function(event) {
      if (_dragCatId === null) return;
      svg.style('cursor', null);
      if (_dragGhost) { _dragGhost.remove(); _dragGhost = null; }
      g.selectAll('.lane-drop-indicator').remove();

      // Re-attach zoom
      svg.call(zoom);

      const t  = _currentTransform;
      const gy = (event.y - t.y) / t.k;

      // Find drop target
      let dropCatId = null;
      for (const [catId, rect] of laneRects) {
        if (catId === _dragCatId) continue;
        if (!_categories.find(c => c.id === catId)) continue;
        if (gy >= rect.y && gy < rect.y + rect.h) { dropCatId = catId; break; }
      }

      if (dropCatId === null || dropCatId === _dragCatId) { _dragCatId = null; return; }

      // Swap positions in _categories array
      const srcIdx = _categories.findIndex(c => c.id === _dragCatId);
      const dstIdx = _categories.findIndex(c => c.id === dropCatId);
      if (srcIdx === -1 || dstIdx === -1) { _dragCatId = null; return; }

      const moved = _categories.splice(srcIdx, 1)[0];
      _categories.splice(dstIdx, 0, moved);

      // Persist new display_order for each category
      _categories.forEach((cat, i) => {
        fetch(`/categories/${cat.id}/update`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: cat.name, color: cat.color, display_order: i })
        });
      });

      _dragCatId = null;
      reflowAndFit(true);
    });

  // Apply drag to the lane background — only the label column region
  g.select('.lane').selectAll('rect').filter(function() {
    return +d3.select(this).attr('x') === 0 && +d3.select(this).attr('width') > LABEL_W;
  }).call(drag);
}

// ── Fit ───────────────────────────────────────────────────────────────────

function fitAll(dur = 0) {
  if (!_allNodes.length) return;
  const W = svgWidth();

  const xs   = _allNodes.map(n => n._x);
  const ys   = _allNodes.map(n => n._y);
  const maxX = Math.max(...xs) + ((_allNodes[0] && _allNodes[0]._nw) || NODE_W) + SIDE_PAD;
  const minY = Math.min(...ys) - ROW_PAD;
  const maxY = Math.max(..._allNodes.map(n => n._y + nodeEffectiveH(n, n._nw))) + ROW_PAD;

  const contentW = maxX;
  const contentH = maxY - minY;

  // Scale to fill width only — height overflows and the container scrolls
  const scale = Math.min(W / contentW, 1);
  const tx = 0;
  const ty = -minY * scale;

  // Size the SVG to its content so the scroll container can scroll it
  svg.attr('height', Math.ceil(contentH * scale) + ROW_PAD);

  svg.transition().duration(dur)
    .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
}

// ── Sidebar ───────────────────────────────────────────────────────────────

function showDefaultSidebar() {
  document.getElementById('sidebarContent').innerHTML = `
    <div class="text-muted small text-center py-4">
      <i class="bi bi-cursor display-6 opacity-25"></i>
      <p class="mt-2">Click a node to see host details</p>
    </div>`;
}

function showHostDetail(d) {
  const portsHtml = d.ports.length
    ? d.ports.map(p => `
        <span class="port-chip">
          <i class="bi bi-unlock-fill" style="font-size:9px"></i>
          ${p.portid}/${p.service || '?'}
          ${p.product ? `<span style="opacity:.6;font-size:8px"> ${p.product}</span>` : ''}
        </span>`).join('')
    : '<span class="text-muted small">No open ports detected</span>';

  const catOptions = _categories.map(c =>
    `<option value="${c.id}" ${d.category_id === c.id ? 'selected' : ''}>${escHtml(c.name)}</option>`
  ).join('');

  document.getElementById('sidebarContent').innerHTML = `
    ${d.ghost ? `
    <div class="px-3 pt-2 pb-1">
      <div class="d-flex align-items-center gap-2 px-2 py-1 rounded"
           style="background:rgba(220,53,69,0.12);border:1px solid rgba(220,53,69,0.3);font-size:11px">
        <span class="rounded-circle flex-shrink-0" style="width:7px;height:7px;background:#dc3545"></span>
        <span class="text-danger">Not seen in current scan</span>
      </div>
    </div>` : ''}
    <div class="host-detail-section">
      <div class="d-flex align-items-center gap-2 mb-3">
        <div class="workspace-icon" style="width:36px;height:36px;font-size:1rem">
          <i class="bi bi-hdd-network${d.ghost ? ' text-danger' : ''}"></i>
        </div>
        <div>
          <div class="fw-semibold">${d.ip}</div>
          ${d.category_name
            ? `<span class="badge" style="background:${d.category_color}22;color:${d.category_color};border:1px solid ${d.category_color}44">${escHtml(d.category_name)}</span>`
            : '<span class="text-muted small fst-italic">No category</span>'}
        </div>
      </div>
    </div>

    <div class="host-detail-section">
      <div class="host-detail-label">Category</div>
      ${d.mac ? `
      <select class="form-select form-select-sm bg-dark border-secondary text-white"
              onchange="assignCategory('${d.mac}', this.value, this)">
        <option value="">— None —</option>
        ${catOptions}
      </select>` : '<span class="text-muted small">No MAC (cannot assign category)</span>'}
    </div>

    <div class="host-detail-section">
      <div class="host-detail-label">Tag</div>
      <div class="input-group input-group-sm">
        <input type="text" id="tagInput-${d.ip.replace(/\./g,'_')}"
               class="form-control bg-dark border-secondary text-white"
               placeholder="e.g. NAS, Camera, Printer…"
               value="${escHtml(d.tag)}">
        <button class="btn btn-outline-warning btn-sm"
          onclick="saveTag('${d.ip}','${escHtml(d.mac)}',document.getElementById('tagInput-${d.ip.replace(/\./g,'_')}').value)">
          <i class="bi bi-check"></i>
        </button>
      </div>
    </div>

    <div class="host-detail-section">
      <div class="host-detail-label">MAC</div>
      ${d.randomized_mac
        ? `<span class="badge" style="background:#3a2000;color:#ffa94d;border:1px solid #ffa94d66">
             <i class="bi bi-shuffle me-1" style="font-size:9px"></i>Randomized
           </span>
           <span class="text-muted small ms-1" style="font-size:10px">(tracked by hostname)</span>`
        : d.mac && !d.mac.startsWith('ip:') && !d.mac.startsWith('hostname:')
          ? `<code class="small text-warning">${escHtml(d.mac)}</code>`
          : '<span class="text-muted small fst-italic">—</span>'}
    </div>

    ${d.hostname ? `<div class="host-detail-section">
      <div class="host-detail-label">Hostname</div>
      <div class="small text-info">${d.hostname}</div>
    </div>` : ''}

    ${d.vendor ? `<div class="host-detail-section">
      <div class="host-detail-label">Vendor</div>
      <div class="small">${d.vendor}</div>
    </div>` : ''}

    ${d.os_name ? `<div class="host-detail-section">
      <div class="host-detail-label">OS</div>
      <div class="small">${d.os_name}</div>
    </div>` : ''}

    <div class="host-detail-section">
      <div class="host-detail-label">Open Ports (${d.ports.length})</div>
      <div class="mt-1">${portsHtml}</div>
    </div>`;
}

// ── Category assignment ───────────────────────────────────────────────────

function assignCategory(mac, categoryId, selectEl) {
  const payload = { category_id: categoryId ? parseInt(categoryId) : null };
  fetch(`/assets/${encodeURIComponent(mac)}/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  .then(r => r.json())
  .then(() => loadGraph())
  .catch(err => console.error('Category assign error:', err));
}

// ── Tag ───────────────────────────────────────────────────────────────────

function saveTag(ip, mac, tag) {
  fetch(`/workspace/${_workspaceSlug}/tag`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, mac, tag: tag.trim() })
  })
  .then(r => r.json())
  .then(() => {
    const node = _allNodes.find(n => n.ip === ip);
    if (node) {
      node.tag = tag.trim();
      g.selectAll('.node').filter(d => d.ip === ip)
        .select('.tag-text')
        .attr('font-style', tag.trim() ? 'normal' : 'italic')
        .attr('fill', tag.trim() ? TAG_COLOR : 'rgba(255,255,255,0.25)')
        .text(tag.trim() || 'add tag…');
    }
  })
  .catch(err => console.error('Tag error:', err));
}

// ── Helpers ───────────────────────────────────────────────────────────────

function trunc(s, n) { return s && s.length > n ? s.substring(0, n - 1) + '…' : (s || ''); }
function escHtml(s)  { return (s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
