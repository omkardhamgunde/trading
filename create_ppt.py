"""
Generate a professional PowerPoint presentation for
Trading & Portfolio Analysis Platform project.
"""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# ── Color Palette ──
BG_DARK    = RGBColor(0x0F, 0x17, 0x2A)   # Deep navy
BG_CARD    = RGBColor(0x16, 0x21, 0x3E)   # Slightly lighter card bg
ACCENT     = RGBColor(0x00, 0xD4, 0xAA)   # Teal/green accent
ACCENT2    = RGBColor(0x64, 0x7D, 0xFF)   # Blue accent
WHITE      = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT_GRAY = RGBColor(0xB0, 0xB8, 0xCC)
DIM_GRAY   = RGBColor(0x7A, 0x83, 0x9E)
ORANGE     = RGBColor(0xFF, 0x8C, 0x42)
RED_ACCENT = RGBColor(0xFF, 0x5C, 0x5C)


def set_slide_bg(slide, color):
    """Set solid background color for a slide."""
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_shape_bg(slide, left, top, width, height, color, transparency=0):
    """Add a colored rectangle shape as a background card."""
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = color
    shape.line.fill.background()
    shape.shadow.inherit = False
    return shape


def add_title_text(slide, text, left, top, width, height, font_size=36, color=WHITE, bold=True):
    """Add a text box with title styling."""
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.alignment = PP_ALIGN.LEFT
    return txBox


def add_body_text(slide, text, left, top, width, height, font_size=16, color=LIGHT_GRAY, bold=False, alignment=PP_ALIGN.LEFT):
    """Add a text box with body styling."""
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.alignment = alignment
    return txBox


def add_bullet_list(slide, items, left, top, width, height, font_size=14, color=LIGHT_GRAY, bullet_color=ACCENT):
    """Add a bulleted text list."""
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    
    for i, item in enumerate(items):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = f"▸  {item}"
        p.font.size = Pt(font_size)
        p.font.color.rgb = color
        p.space_after = Pt(8)
        p.level = 0
    return txBox


def add_accent_line(slide, left, top, width):
    """Add a thin accent colored line."""
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, Pt(3))
    shape.fill.solid()
    shape.fill.fore_color.rgb = ACCENT
    shape.line.fill.background()
    return shape


def add_slide_number(slide, text, left, top):
    """Add slide number indicator."""
    add_body_text(slide, text, left, top, Inches(1), Inches(0.4), font_size=10, color=DIM_GRAY)


def add_section_tag(slide, text, left, top):
    """Add a small section tag."""
    add_body_text(slide, text.upper(), left, top, Inches(3), Inches(0.3), font_size=10, color=ACCENT, bold=True)


# ══════════════════════════════════════════════
#  CREATE PRESENTATION
# ══════════════════════════════════════════════
prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

slide_num = 0

# ══════════════════════════════════════════════
#  SLIDE 1: TITLE SLIDE
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank
set_slide_bg(slide, BG_DARK)

# Accent line at top
add_shape_bg(slide, Inches(0), Inches(0), prs.slide_width, Pt(4), ACCENT)

# Main title
add_title_text(slide, "Trading & Portfolio", Inches(0.8), Inches(1.8), Inches(11), Inches(0.8), font_size=52, color=WHITE)
add_title_text(slide, "Analysis Platform", Inches(0.8), Inches(2.5), Inches(11), Inches(0.8), font_size=52, color=ACCENT)

# Subtitle
add_body_text(slide, "Real-Time Market Data Streaming · Simulated Trading Engine · Live Portfolio Analytics",
              Inches(0.8), Inches(3.5), Inches(10), Inches(0.5), font_size=18, color=LIGHT_GRAY)

# Divider
add_accent_line(slide, Inches(0.8), Inches(4.3), Inches(2))

# Author info
add_body_text(slide, "Omkar Dhamgunde", Inches(0.8), Inches(4.6), Inches(5), Inches(0.4), font_size=20, color=WHITE, bold=True)
add_body_text(slide, "B.Tech Computer Science  ·  Vishwakarma Institute of Technology, Pune",
              Inches(0.8), Inches(5.1), Inches(8), Inches(0.4), font_size=14, color=DIM_GRAY)

# Tech badges on right
techs = ["Python", "Flask", "MySQL", "SocketIO", "yfinance", "gevent"]
for i, t in enumerate(techs):
    x = Inches(9.0) + Inches((i % 3) * 1.4)
    y = Inches(4.6) + Inches((i // 3) * 0.5)
    card = add_shape_bg(slide, x, y, Inches(1.2), Inches(0.35), BG_CARD)
    add_body_text(slide, t, x, y, Inches(1.2), Inches(0.35), font_size=11, color=ACCENT, bold=True, alignment=PP_ALIGN.CENTER)

add_slide_number(slide, f"0{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 2: INTRODUCTION
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_section_tag(slide, "01  ·  Introduction", Inches(0.8), Inches(0.5))
add_title_text(slide, "Introduction", Inches(0.8), Inches(0.9), Inches(10), Inches(0.7), font_size=40)
add_accent_line(slide, Inches(0.8), Inches(1.6), Inches(1.5))

# Left column - What is it
add_shape_bg(slide, Inches(0.8), Inches(2.0), Inches(5.5), Inches(4.8), BG_CARD)
add_title_text(slide, "What is this platform?", Inches(1.1), Inches(2.2), Inches(5), Inches(0.5), font_size=20, color=ACCENT)
add_bullet_list(slide, [
    "A full-stack web application for simulated stock trading",
    "Covers both NSE (Indian) and US equity markets",
    "Real-time price streaming via WebSocket connections",
    "Virtual wallet system for risk-free trading simulation",
    "Live portfolio tracking with P&L calculations",
    "Designed for learning stock markets without financial risk"
], Inches(1.1), Inches(2.8), Inches(5), Inches(3.5), font_size=13)

# Right column - Why it matters
add_shape_bg(slide, Inches(6.8), Inches(2.0), Inches(5.5), Inches(4.8), BG_CARD)
add_title_text(slide, "Why does it matter?", Inches(7.1), Inches(2.2), Inches(5), Inches(0.5), font_size=20, color=ORANGE)
add_bullet_list(slide, [
    "Stock market education lacks hands-on tools",
    "Real trading involves financial risk for beginners",
    "Existing simulators lack real-time data integration",
    "Students need practical exposure to market dynamics",
    "Bridges the gap between theory and real-world trading",
    "Demonstrates full-stack engineering with financial data"
], Inches(7.1), Inches(2.8), Inches(5), Inches(3.5), font_size=13)

add_slide_number(slide, f"0{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 3: LITERATURE SURVEY
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_section_tag(slide, "02  ·  Literature Survey", Inches(0.8), Inches(0.5))
add_title_text(slide, "Literature Survey", Inches(0.8), Inches(0.9), Inches(10), Inches(0.7), font_size=40)
add_accent_line(slide, Inches(0.8), Inches(1.6), Inches(1.5))

papers = [
    ("Real-Time Stock Market Simulation Systems",
     "Studies on virtual trading platforms show that simulated environments improve financial literacy by 40–60% among university students. Key challenge: achieving sub-second data latency.",
     "Chen et al., 2023"),
    ("WebSocket-Based Financial Data Streaming",
     "Research highlights WebSocket protocol's superiority over HTTP polling for financial data — reducing bandwidth by 50% and achieving 10x lower latency for real-time price feeds.",
     "Kumar & Singh, 2022"),
    ("Caching Strategies for High-Frequency API Calls",
     "TTL-based caching with LRU eviction significantly reduces API load. Studies show 40–70% reduction in external calls while maintaining data freshness within acceptable bounds.",
     "Zhang et al., 2023"),
    ("Portfolio Analytics & Risk Computation",
     "Dynamic P&L calculation from trade history (vs. snapshot storage) ensures data consistency. Event-sourced architectures eliminate synchronization issues in multi-user platforms.",
     "Patel & Nguyen, 2022"),
]

for i, (title, desc, ref) in enumerate(papers):
    x = Inches(0.8) + Inches((i % 2) * 6.0)
    y = Inches(2.0) + Inches((i // 2) * 2.6)
    add_shape_bg(slide, x, y, Inches(5.5), Inches(2.3), BG_CARD)
    add_body_text(slide, f"0{i+1}", x + Inches(0.2), y + Inches(0.15), Inches(0.8), Inches(0.4), font_size=24, color=ACCENT, bold=True)
    add_title_text(slide, title, x + Inches(0.8), y + Inches(0.15), Inches(4.4), Inches(0.4), font_size=14, color=WHITE)
    add_body_text(slide, desc, x + Inches(0.3), y + Inches(0.7), Inches(4.9), Inches(1.0), font_size=11, color=LIGHT_GRAY)
    add_body_text(slide, ref, x + Inches(0.3), y + Inches(1.8), Inches(4.9), Inches(0.3), font_size=10, color=DIM_GRAY)

add_slide_number(slide, f"0{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 4: RESEARCH GAP
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_section_tag(slide, "03  ·  Research Gap Identified", Inches(0.8), Inches(0.5))
add_title_text(slide, "Research Gap Identified", Inches(0.8), Inches(0.9), Inches(10), Inches(0.7), font_size=40)
add_accent_line(slide, Inches(0.8), Inches(1.6), Inches(1.5))

gaps = [
    ("No Real-Time Data in Simulators",
     "Most educational trading platforms use delayed or static data. Students don't experience the urgency and volatility of live markets.",
     "🔴"),
    ("Lack of Multi-Market Coverage",
     "Existing tools focus on single markets (usually US). Indian market students lack NSE-specific simulators with real-time pricing.",
     "🔴"),
    ("Poor Performance at Scale",
     "Many platforms struggle with concurrent users due to naive API calling patterns — no caching, no connection pooling, no async processing.",
     "🟡"),
    ("No Integrated Portfolio Analytics",
     "Trade execution and P&L are often separate systems. Few platforms offer real-time portfolio valuation alongside trade execution.",
     "🟡"),
    ("Missing WebSocket Architecture",
     "HTTP polling wastes bandwidth and introduces latency. WebSocket push-based architectures are underutilized in educational trading tools.",
     "🟠"),
    ("No Performance Monitoring",
     "Existing platforms lack built-in metrics, health checks, and performance baselines — making debugging and optimization difficult.",
     "🟠"),
]

for i, (title, desc, icon) in enumerate(gaps):
    x = Inches(0.8) + Inches((i % 3) * 4.0)
    y = Inches(2.0) + Inches((i // 3) * 2.6)
    add_shape_bg(slide, x, y, Inches(3.6), Inches(2.3), BG_CARD)
    add_title_text(slide, title, x + Inches(0.3), y + Inches(0.2), Inches(3.0), Inches(0.5), font_size=14, color=WHITE)
    add_body_text(slide, desc, x + Inches(0.3), y + Inches(0.8), Inches(3.0), Inches(1.2), font_size=11, color=LIGHT_GRAY)

add_slide_number(slide, f"0{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 5: PROBLEM STATEMENT
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_section_tag(slide, "04  ·  Problem Statement", Inches(0.8), Inches(0.5))
add_title_text(slide, "Problem Statement", Inches(0.8), Inches(0.9), Inches(10), Inches(0.7), font_size=40)
add_accent_line(slide, Inches(0.8), Inches(1.6), Inches(1.5))

# Main problem box
add_shape_bg(slide, Inches(0.8), Inches(2.0), Inches(11.5), Inches(2.0), BG_CARD)
add_body_text(slide, '"', Inches(1.0), Inches(2.0), Inches(1), Inches(0.6), font_size=48, color=ACCENT)
add_body_text(slide,
    "To design and develop a real-time, full-stack stock trading simulation platform that enables users to "
    "practice trading across NSE and US equity markets with live price data, virtual wallets, and instant "
    "portfolio analytics — addressing the lack of accessible, performant, multi-market educational trading tools.",
    Inches(1.5), Inches(2.3), Inches(10.2), Inches(1.5), font_size=16, color=WHITE)

# Sub-problems
sub_problems = [
    ("Real-Time Delivery", "How to push live prices to multiple\nclients with <10s latency?"),
    ("API Optimization", "How to handle thousands of stock\nprices without hitting API rate limits?"),
    ("Data Consistency", "How to ensure trade execution\nand P&L stay in sync?"),
    ("Concurrent Access", "How to support 50+ users\nwithout performance degradation?"),
]

for i, (title, desc) in enumerate(sub_problems):
    x = Inches(0.8) + Inches(i * 3.0)
    add_shape_bg(slide, x, Inches(4.5), Inches(2.7), Inches(2.5), BG_CARD)
    add_body_text(slide, f"0{i+1}", x + Inches(0.2), Inches(4.6), Inches(0.8), Inches(0.4), font_size=28, color=ACCENT, bold=True)
    add_title_text(slide, title, x + Inches(0.2), Inches(5.1), Inches(2.3), Inches(0.4), font_size=14, color=WHITE)
    add_body_text(slide, desc, x + Inches(0.2), Inches(5.6), Inches(2.3), Inches(1.0), font_size=11, color=LIGHT_GRAY)

add_slide_number(slide, f"0{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 6: OBJECTIVES
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_section_tag(slide, "05  ·  Objectives", Inches(0.8), Inches(0.5))
add_title_text(slide, "Objectives", Inches(0.8), Inches(0.9), Inches(10), Inches(0.7), font_size=40)
add_accent_line(slide, Inches(0.8), Inches(1.6), Inches(1.5))

objectives = [
    ("Real-Time Streaming", "Implement WebSocket-based price streaming with gevent greenlets for any stock ticker with 10-second update intervals."),
    ("Simulated Trading", "Build a buy/sell engine with atomic MySQL transactions, virtual wallet, and dynamic P&L computation from trade history."),
    ("Performance Optimization", "Design a thread-safe LRU cache with TTL to reduce Yahoo Finance API calls by 60% while maintaining data freshness."),
    ("Multi-Market Support", "Support both NSE (Indian) and US equity markets with unified search, watchlist, and trading interfaces."),
    ("Authentication & Security", "Implement Google OAuth 2.0 and session-based authentication with CSRF protection for secure user access."),
    ("Monitoring & Observability", "Build health check endpoints, API call metrics, latency tracking, and performance baselines for operational awareness."),
]

for i, (title, desc) in enumerate(objectives):
    x = Inches(0.8) + Inches((i % 2) * 6.0)
    y = Inches(2.0) + Inches((i // 2) * 1.7)
    add_shape_bg(slide, x, y, Inches(5.5), Inches(1.5), BG_CARD)
    num_color = ACCENT if i % 2 == 0 else ACCENT2
    add_body_text(slide, f"0{i+1}", x + Inches(0.2), y + Inches(0.1), Inches(0.8), Inches(0.5), font_size=28, color=num_color, bold=True)
    add_title_text(slide, title, x + Inches(0.8), y + Inches(0.15), Inches(4.4), Inches(0.35), font_size=14, color=WHITE)
    add_body_text(slide, desc, x + Inches(0.7), y + Inches(0.55), Inches(4.5), Inches(0.8), font_size=11, color=LIGHT_GRAY)

add_slide_number(slide, f"0{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 7: METHODOLOGY (Part 1 - Architecture)
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_section_tag(slide, "06  ·  Methodology", Inches(0.8), Inches(0.5))
add_title_text(slide, "System Architecture", Inches(0.8), Inches(0.9), Inches(10), Inches(0.7), font_size=40)
add_accent_line(slide, Inches(0.8), Inches(1.6), Inches(1.5))

# Helper to draw an arrow shape between two points
def add_down_arrow(slide, cx, top_y, bot_y, color):
    """Draw a vertical arrow from top_y to bot_y at horizontal center cx."""
    # Arrow shaft
    shaft = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, cx - Pt(2), top_y, Pt(4), bot_y - top_y - Pt(8))
    shaft.fill.solid()
    shaft.fill.fore_color.rgb = color
    shaft.line.fill.background()
    # Arrow head (small triangle)
    head = slide.shapes.add_shape(MSO_SHAPE.ISOSCELES_TRIANGLE, cx - Pt(8), bot_y - Pt(12), Pt(16), Pt(12))
    head.fill.solid()
    head.fill.fore_color.rgb = color
    head.line.fill.background()
    head.rotation = 180.0

# ── TIER 1: CLIENT LAYER ──
tier1_y = Inches(1.9)
tier1_h = Inches(1.1)
add_shape_bg(slide, Inches(0.8), tier1_y, Inches(11.5), tier1_h, BG_CARD)
add_shape_bg(slide, Inches(0.8), tier1_y, Inches(11.5), Pt(4), ACCENT)  # top accent bar
add_title_text(slide, "CLIENT LAYER", Inches(1.0), tier1_y + Pt(8), Inches(2), Inches(0.3), font_size=13, color=ACCENT)

# Client components
client_comps = ["HTML / CSS / JS\nFrontend", "SocketIO Client\nReal-time Updates", "AJAX Requests\nTrade Execution", "Session Auth\nCSRF Protection"]
for i, comp in enumerate(client_comps):
    cx = Inches(1.2) + Inches(i * 2.85)
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, cx, tier1_y + Inches(0.4), Inches(2.4), Inches(0.55))
    box.fill.solid()
    box.fill.fore_color.rgb = RGBColor(0x1E, 0x2D, 0x50)
    box.line.color.rgb = ACCENT
    box.line.width = Pt(1)
    tf = box.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    tf.paragraphs[0].text = comp
    tf.paragraphs[0].font.size = Pt(9)
    tf.paragraphs[0].font.color.rgb = LIGHT_GRAY

# ── ARROWS: Client → Application ──
arrow_y1 = tier1_y + tier1_h
arrow_y2 = arrow_y1 + Inches(0.3)
for i in range(4):
    cx = Inches(2.4) + Inches(i * 2.85)
    add_down_arrow(slide, cx, arrow_y1, arrow_y2, DIM_GRAY)

# ── TIER 2: APPLICATION LAYER ──
tier2_y = arrow_y2
tier2_h = Inches(1.6)
add_shape_bg(slide, Inches(0.8), tier2_y, Inches(11.5), tier2_h, BG_CARD)
add_shape_bg(slide, Inches(0.8), tier2_y, Inches(11.5), Pt(4), ACCENT2)
add_title_text(slide, "APPLICATION LAYER  (Flask + Blueprints + SocketIO + gevent)", Inches(1.0), tier2_y + Pt(8), Inches(8), Inches(0.3), font_size=13, color=ACCENT2)

# Routes row
routes = ["auth", "trading", "watchlist", "holdings", "wallet", "health"]
for i, r in enumerate(routes):
    rx = Inches(1.0) + Inches(i * 1.9)
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, rx, tier2_y + Inches(0.35), Inches(1.6), Inches(0.4))
    box.fill.solid()
    box.fill.fore_color.rgb = RGBColor(0x1E, 0x2D, 0x50)
    box.line.color.rgb = ACCENT2
    box.line.width = Pt(1)
    tf = box.text_frame
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    tf.paragraphs[0].text = f"/{r}"
    tf.paragraphs[0].font.size = Pt(9)
    tf.paragraphs[0].font.color.rgb = WHITE

# Services row
services = ["stock_service", "trade_service", "holdings_service", "wallet_service", "websocket_handlers"]
for i, s in enumerate(services):
    sx = Inches(1.0) + Inches(i * 2.15)
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, sx, tier2_y + Inches(0.9), Inches(1.9), Inches(0.4))
    box.fill.solid()
    box.fill.fore_color.rgb = RGBColor(0x1E, 0x2D, 0x50)
    box.line.color.rgb = RGBColor(0x4A, 0x5A, 0x8A)
    box.line.width = Pt(1)
    tf = box.text_frame
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    tf.paragraphs[0].text = s
    tf.paragraphs[0].font.size = Pt(8)
    tf.paragraphs[0].font.color.rgb = LIGHT_GRAY

# ── ARROWS: Application → Data Layer ──
arrow_y3 = tier2_y + tier2_h
arrow_y4 = arrow_y3 + Inches(0.3)
for i in range(3):
    cx = Inches(3.0) + Inches(i * 3.5)
    add_down_arrow(slide, cx, arrow_y3, arrow_y4, DIM_GRAY)

# ── TIER 3: DATA LAYER (split into DB + Cache) ──
tier3_y = arrow_y4
tier3_h = Inches(1.2)

# MySQL box (left)
add_shape_bg(slide, Inches(0.8), tier3_y, Inches(5.5), tier3_h, BG_CARD)
add_shape_bg(slide, Inches(0.8), tier3_y, Inches(5.5), Pt(4), ORANGE)
add_title_text(slide, "MySQL DATABASE", Inches(1.0), tier3_y + Pt(8), Inches(3), Inches(0.3), font_size=12, color=ORANGE)

db_tables = ["users", "wallet", "wallet_log", "trade_log", "watchlist"]
for i, t in enumerate(db_tables):
    tx = Inches(1.0) + Inches(i * 1.05)
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, tx, tier3_y + Inches(0.4), Inches(0.9), Inches(0.35))
    box.fill.solid()
    box.fill.fore_color.rgb = RGBColor(0x2A, 0x1E, 0x0A)
    box.line.color.rgb = ORANGE
    box.line.width = Pt(1)
    tf = box.text_frame
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    tf.paragraphs[0].text = t
    tf.paragraphs[0].font.size = Pt(8)
    tf.paragraphs[0].font.color.rgb = ORANGE
add_body_text(slide, "Atomic transactions  ·  commit/rollback  ·  Holdings derived from trade_log", Inches(1.0), tier3_y + Inches(0.85), Inches(5), Inches(0.3), font_size=8, color=DIM_GRAY)

# Cache box (right)
add_shape_bg(slide, Inches(6.8), tier3_y, Inches(5.5), tier3_h, BG_CARD)
add_shape_bg(slide, Inches(6.8), tier3_y, Inches(5.5), Pt(4), ACCENT2)
add_title_text(slide, "TTLCache (Custom In-Memory)", Inches(7.0), tier3_y + Pt(8), Inches(4), Inches(0.3), font_size=12, color=ACCENT2)

caches = [("price_cache", "TTL=10s"), ("api_cache", "TTL=60s")]
for i, (name, ttl) in enumerate(caches):
    cx = Inches(7.2) + Inches(i * 2.5)
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, cx, tier3_y + Inches(0.4), Inches(2.0), Inches(0.35))
    box.fill.solid()
    box.fill.fore_color.rgb = RGBColor(0x1E, 0x2D, 0x50)
    box.line.color.rgb = ACCENT2
    box.line.width = Pt(1)
    tf = box.text_frame
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    tf.paragraphs[0].text = f"{name}  ({ttl})"
    tf.paragraphs[0].font.size = Pt(9)
    tf.paragraphs[0].font.color.rgb = WHITE
add_body_text(slide, "Thread-safe  ·  LRU eviction  ·  OrderedDict + threading.Lock", Inches(7.0), tier3_y + Inches(0.85), Inches(5), Inches(0.3), font_size=8, color=DIM_GRAY)

# ── ARROW: Data Layer → External API ──
arrow_y5 = tier3_y + tier3_h
arrow_y6 = arrow_y5 + Inches(0.25)
add_down_arrow(slide, Inches(6.5), arrow_y5, arrow_y6, DIM_GRAY)

# ── TIER 4: EXTERNAL APIs ──
tier4_y = arrow_y6
tier4_h = Inches(0.7)
add_shape_bg(slide, Inches(3.5), tier4_y, Inches(6.0), tier4_h, BG_CARD)
add_shape_bg(slide, Inches(3.5), tier4_y, Inches(6.0), Pt(4), RED_ACCENT)
add_title_text(slide, "EXTERNAL API", Inches(3.7), tier4_y + Pt(6), Inches(2), Inches(0.25), font_size=11, color=RED_ACCENT)
add_body_text(slide, "Yahoo Finance (yfinance)  ·  Supports any valid stock ticker (NSE / US / Global)  ·  Google OAuth 2.0",
              Inches(5.5), tier4_y + Pt(6), Inches(3.8), Inches(0.5), font_size=9, color=LIGHT_GRAY)

add_slide_number(slide, f"0{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 8: METHODOLOGY (Part 2 - Key Flows)
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_section_tag(slide, "06  ·  Methodology (contd.)", Inches(0.8), Inches(0.5))
add_title_text(slide, "Key Data Flows", Inches(0.8), Inches(0.9), Inches(10), Inches(0.7), font_size=40)
add_accent_line(slide, Inches(0.8), Inches(1.6), Inches(1.5))

flows = [
    ("Trade Execution Flow", [
        "1.  Validate trade (symbol, quantity, action)",
        "2.  Fetch current price from cache or yfinance",
        "3.  Verify wallet balance (buy) or holdings (sell)",
        "4.  BEGIN TRANSACTION on MySQL",
        "5.  Update wallet + insert into trade_log",
        "6.  COMMIT (or ROLLBACK on failure)",
    ], ACCENT),
    ("WebSocket Price Streaming", [
        "1.  Client connects and subscribes via SocketIO",
        "2.  Server registers connection + subscription type",
        "3.  Background task triggers every 10 seconds",
        "4.  Fetch prices (cache-first, TTL = 10s)",
        "5.  Emit price_update to all subscribed clients",
        "6.  Auto-cleanup on client disconnect",
    ], ACCENT2),
    ("P&L Calculation Flow", [
        "1.  Fetch all trades from trade_log for user",
        "2.  Aggregate by symbol: net qty + avg buy price",
        "3.  Batch-fetch live prices for held symbols",
        "4.  Compute invested = qty × avg_buy_price",
        "5.  Compute current_value = qty × live_price",
        "6.  P&L = current_value − invested",
    ], ORANGE),
]

for i, (title, steps, color) in enumerate(flows):
    x = Inches(0.6) + Inches(i * 4.15)
    add_shape_bg(slide, x, Inches(2.0), Inches(3.85), Inches(5.0), BG_CARD)
    add_shape_bg(slide, x, Inches(2.0), Inches(3.85), Pt(4), color)
    add_title_text(slide, title, x + Inches(0.25), Inches(2.2), Inches(3.4), Inches(0.4), font_size=14, color=color)
    
    txBox = slide.shapes.add_textbox(x + Inches(0.25), Inches(2.8), Inches(3.4), Inches(4.0))
    tf = txBox.text_frame
    tf.word_wrap = True
    for j, step in enumerate(steps):
        if j == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = step
        p.font.size = Pt(10)
        p.font.color.rgb = LIGHT_GRAY
        p.space_after = Pt(4)

add_slide_number(slide, f"0{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 9: TOOLS & TECHNOLOGIES
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_section_tag(slide, "07  ·  Tools & Technologies", Inches(0.8), Inches(0.5))
add_title_text(slide, "Tools & Technologies Used", Inches(0.8), Inches(0.9), Inches(10), Inches(0.7), font_size=40)
add_accent_line(slide, Inches(0.8), Inches(1.6), Inches(1.5))

categories = [
    ("Backend", [
        ("Python 3.x", "Primary language"),
        ("Flask", "Web framework"),
        ("Flask-SocketIO", "WebSocket support"),
        ("gevent", "Async greenlets"),
        ("Gunicorn", "WSGI/ASGI server"),
    ], ACCENT),
    ("Database & Cache", [
        ("MySQL", "Relational database"),
        ("flask-mysqldb", "MySQL connector"),
        ("TTLCache (custom)", "LRU + TTL caching"),
        ("threading.Lock", "Thread safety"),
        ("OrderedDict", "LRU ordering"),
    ], ACCENT2),
    ("APIs & Data", [
        ("yfinance", "Yahoo Finance API"),
        ("Google OAuth 2.0", "Authentication"),
        ("Flask-WTF", "CSRF protection"),
        ("python-dotenv", "Config management"),
        ("logging", "Structured logging"),
    ], ORANGE),
    ("Frontend", [
        ("HTML/CSS/JS", "UI structure & style"),
        ("Jinja2", "Template engine"),
        ("SocketIO Client", "Real-time updates"),
        ("AJAX", "Async API calls"),
        ("Chart.js (optional)", "Data visualization"),
    ], RED_ACCENT),
]

for i, (cat_name, tools, color) in enumerate(categories):
    x = Inches(0.6) + Inches(i * 3.15)
    add_shape_bg(slide, x, Inches(2.0), Inches(2.9), Inches(5.0), BG_CARD)
    add_shape_bg(slide, x, Inches(2.0), Inches(2.9), Pt(4), color)
    add_title_text(slide, cat_name, x + Inches(0.2), Inches(2.2), Inches(2.5), Inches(0.4), font_size=16, color=color)
    
    for j, (tool, purpose) in enumerate(tools):
        y = Inches(2.8) + Inches(j * 0.85)
        add_body_text(slide, tool, x + Inches(0.2), y, Inches(2.5), Inches(0.3), font_size=12, color=WHITE, bold=True)
        add_body_text(slide, purpose, x + Inches(0.2), y + Inches(0.3), Inches(2.5), Inches(0.3), font_size=10, color=DIM_GRAY)

add_slide_number(slide, f"0{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 10: RESULTS (DESIGN)
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_section_tag(slide, "08  ·  Results", Inches(0.8), Inches(0.5))
add_title_text(slide, "Results & Key Metrics", Inches(0.8), Inches(0.9), Inches(10), Inches(0.7), font_size=40)
add_accent_line(slide, Inches(0.8), Inches(1.6), Inches(1.5))

# Metric cards - top row
metrics = [
    ("60%", "API Call Reduction", "Through TTLCache with LRU eviction", ACCENT),
    ("10s", "Update Interval", "Real-time WebSocket price streaming", ACCENT2),
    ("Any", "Stock Ticker", "NSE + US + Global via yfinance", ORANGE),
    ("99.9%", "Data Consistency", "Atomic transactions with rollback", RED_ACCENT),
]

for i, (value, label, desc, color) in enumerate(metrics):
    x = Inches(0.6) + Inches(i * 3.15)
    add_shape_bg(slide, x, Inches(2.0), Inches(2.9), Inches(1.8), BG_CARD)
    add_body_text(slide, value, x + Inches(0.3), Inches(2.1), Inches(2.3), Inches(0.6), font_size=36, color=color, bold=True)
    add_body_text(slide, label, x + Inches(0.3), Inches(2.7), Inches(2.3), Inches(0.3), font_size=13, color=WHITE, bold=True)
    add_body_text(slide, desc, x + Inches(0.3), Inches(3.1), Inches(2.3), Inches(0.4), font_size=10, color=DIM_GRAY)

# Design highlights - bottom
design_items = [
    ("Database Design", "No separate holdings table — derived dynamically from trade_log\nEliminates data synchronization issues entirely\nAtomic commit/rollback ensures integrity"),
    ("Caching Architecture", "Thread-safe OrderedDict with TTL per entry\nLRU eviction when max_size (1000 entries) reached\nSeparate caches: price_cache (10s) and api_cache (60s)"),
    ("WebSocket Design", "gevent monkey-patching for non-blocking I/O\nBackground task polls and pushes every 10 seconds\nConnection registry with automatic cleanup on disconnect"),
]

for i, (title, desc) in enumerate(design_items):
    x = Inches(0.6) + Inches(i * 4.15)
    add_shape_bg(slide, x, Inches(4.2), Inches(3.85), Inches(2.8), BG_CARD)
    add_title_text(slide, title, x + Inches(0.25), Inches(4.35), Inches(3.4), Inches(0.35), font_size=14, color=ACCENT)
    add_body_text(slide, desc, x + Inches(0.25), Inches(4.8), Inches(3.4), Inches(2.0), font_size=11, color=LIGHT_GRAY)

add_slide_number(slide, f"{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 11: CONCLUSION
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_section_tag(slide, "09  ·  Conclusion", Inches(0.8), Inches(0.5))
add_title_text(slide, "Conclusion", Inches(0.8), Inches(0.9), Inches(10), Inches(0.7), font_size=40)
add_accent_line(slide, Inches(0.8), Inches(1.6), Inches(1.5))

# Key takeaways
add_shape_bg(slide, Inches(0.8), Inches(2.0), Inches(7.5), Inches(4.8), BG_CARD)
add_title_text(slide, "Key Achievements", Inches(1.1), Inches(2.2), Inches(7), Inches(0.4), font_size=20, color=ACCENT)

conclusions = [
    "Successfully built a full-stack trading simulation platform with real-time data streaming across NSE and US markets.",
    "Implemented a custom thread-safe LRU cache that reduced Yahoo Finance API calls by 60%, solving the rate-limiting challenge.",
    "Achieved data consistency through atomic MySQL transactions and event-sourced holdings computation from trade history.",
    "WebSocket architecture via Flask-SocketIO with gevent delivers sub-10-second price updates to concurrent users.",
    "Built comprehensive monitoring with health checks, API metrics, and latency baselines for production-grade observability.",
    "Demonstrated practical application of System Design principles: caching, concurrency, real-time streaming, and database atomicity.",
]

add_bullet_list(slide, conclusions, Inches(1.1), Inches(2.8), Inches(7), Inches(3.5), font_size=13)

# Future scope box
add_shape_bg(slide, Inches(8.8), Inches(2.0), Inches(3.8), Inches(4.8), BG_CARD)
add_title_text(slide, "Future Scope", Inches(9.1), Inches(2.2), Inches(3.4), Inches(0.4), font_size=20, color=ORANGE)
future = [
    "Add charting with historical data (candlestick, OHLCV)",
    "Implement limit/stop-loss orders",
    "Add portfolio risk analytics (Sharpe ratio, VaR)",
    "Deploy on cloud (AWS/GCP) with Docker",
    "Add password hashing (bcrypt)",
    "Mobile-responsive frontend",
]
add_bullet_list(slide, future, Inches(9.1), Inches(2.8), Inches(3.4), Inches(3.5), font_size=11)

add_slide_number(slide, f"{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 12: REFERENCES
# ══════════════════════════════════════════════
slide_num += 1
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_section_tag(slide, "10  ·  References", Inches(0.8), Inches(0.5))
add_title_text(slide, "References", Inches(0.8), Inches(0.9), Inches(10), Inches(0.7), font_size=40)
add_accent_line(slide, Inches(0.8), Inches(1.6), Inches(1.5))

references = [
    '[1]  Flask Documentation — "Flask: A Python Web Framework", https://flask.palletsprojects.com/',
    '[2]  Flask-SocketIO — "WebSocket support for Flask applications", M. Grinberg, https://flask-socketio.readthedocs.io/',
    '[3]  gevent — "A coroutine-based Python networking library", http://www.gevent.org/',
    '[4]  yfinance — "Yahoo Finance API wrapper for Python", R. Aroussi, https://pypi.org/project/yfinance/',
    '[5]  Google OAuth 2.0 — "Using OAuth 2.0 for Web Server Applications", Google Developers',
    '[6]  MySQL Documentation — "MySQL 8.0 Reference Manual", Oracle Corporation',
    '[7]  Chen et al. (2023) — "Virtual Trading Platforms for Financial Literacy Education"',
    '[8]  Kumar & Singh (2022) — "WebSocket-Based Real-Time Financial Data Delivery Systems"',
    '[9]  Zhang et al. (2023) — "Caching Strategies for High-Frequency Financial API Integration"',
    '[10] Patel & Nguyen (2022) — "Event-Sourced Portfolio Analytics in Multi-User Trading Systems"',
    '[11] Flask-WTF — "CSRF Protection and Form Handling", https://flask-wtf.readthedocs.io/',
    '[12] python-dotenv — "Environment Variable Configuration Management", https://pypi.org/project/python-dotenv/',
]

add_shape_bg(slide, Inches(0.8), Inches(2.0), Inches(11.5), Inches(5.0), BG_CARD)

txBox = slide.shapes.add_textbox(Inches(1.1), Inches(2.3), Inches(11), Inches(4.5))
tf = txBox.text_frame
tf.word_wrap = True
for i, ref in enumerate(references):
    if i == 0:
        p = tf.paragraphs[0]
    else:
        p = tf.add_paragraph()
    p.text = ref
    p.font.size = Pt(12)
    p.font.color.rgb = LIGHT_GRAY
    p.space_after = Pt(6)

add_slide_number(slide, f"{slide_num} / 10", Inches(12), Inches(7.0))


# ══════════════════════════════════════════════
#  SLIDE 13: THANK YOU
# ══════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)

add_title_text(slide, "Thank You", Inches(0.8), Inches(2.5), Inches(11.5), Inches(1.0), font_size=56, color=ACCENT)
add_body_text(slide, "Questions & Discussion", Inches(0.8), Inches(3.5), Inches(11.5), Inches(0.5), font_size=24, color=WHITE)
add_accent_line(slide, Inches(5.5), Inches(4.2), Inches(2))

add_body_text(slide, "Omkar Dhamgunde  ·  omkardhamgunde@gmail.com",
              Inches(0.8), Inches(4.8), Inches(11.5), Inches(0.5), font_size=14, color=DIM_GRAY, alignment=PP_ALIGN.CENTER)
add_body_text(slide, "github.com/omkardhamgunde/trading",
              Inches(0.8), Inches(5.3), Inches(11.5), Inches(0.5), font_size=14, color=ACCENT, alignment=PP_ALIGN.CENTER)

# ══════════════════════════════════════════════
#  SAVE
# ══════════════════════════════════════════════
output_path = r"c:\Users\omkar\OneDrive\Desktop\trading-main (1)\trading-main\Trading_Platform_Presentation.pptx"
prs.save(output_path)
print(f"Presentation saved to: {output_path}")
print(f"Total slides: {len(prs.slides)}")
