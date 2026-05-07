"""
dashboard/layouts/report_writer.py
───────────────────────────────────
The "write your report" page.

Routes here:
  /report/<session_id>                  — default to first template available
  /report/<session_id>/<report_type>    — specific template (incident or pentest)

Layout:
  - Header: session info, scenario, template name, submit button
  - Two columns:
    Left (main):  textareas, one per section, with prompts and word counters
    Right (side): session facts (MITRE IDs, hostnames, etc.) — the "evidence panel"
  - Bottom: Save Draft + Submit buttons
  - After submit: scorecard with breakdown + feedback
"""

from __future__ import annotations

from dash import dcc, html


def _section_card(section_id: str, title: str, prompt: str, placeholder: str,
                  required: bool, min_words: int) -> html.Div:
    """One card per report section."""
    return html.Div(
        [
            html.Div(
                [
                    html.Div(
                        [
                            html.Span(title, className="rw-section-title"),
                            html.Span(
                                "REQUIRED" if required else "OPTIONAL",
                                className=f"rw-required-tag {'required' if required else 'optional'}",
                            ),
                        ],
                        className="rw-section-header-row",
                    ),
                    html.Div(prompt, className="rw-section-prompt"),
                ],
                className="rw-section-header",
            ),
            dcc.Textarea(
                id={"type": "rw-section", "section": section_id},
                placeholder=placeholder,
                className="rw-textarea",
                style={"width": "100%", "height": "180px"},
                value="",
            ),
            html.Div(
                [
                    html.Span(
                        id={"type": "rw-wordcount", "section": section_id},
                        children="0 words",
                        className="rw-wordcount",
                    ),
                    html.Span(
                        f"target: {min_words}+ words",
                        className="rw-wordtarget",
                    ),
                ],
                className="rw-section-footer",
            ),
        ],
        className="rw-section-card",
    )


def _facts_panel() -> html.Div:
    """Side panel showing session facts (the evidence the student should cite)."""
    return html.Div(
        [
            html.Div(
                [
                    html.H3("Session Evidence", className="astra-card-title"),
                    html.Span("REFERENCE THIS", className="astra-card-meta"),
                ],
                className="astra-card-header",
            ),
            html.P(
                "Include specific items from this list to score well on Specificity. "
                "A good report cites real MITRE IDs, hostnames, and IOCs from the session.",
                className="rw-facts-intro",
            ),
            html.Div(id="rw-facts-content", className="rw-facts-body"),
        ],
        className="astra-card rw-facts-panel",
    )


def _submit_bar() -> html.Div:
    return html.Div(
        [
            html.Div(
                [
                    html.Span("Status: ", className="rw-status-label"),
                    html.Span("Draft", id="rw-status", className="rw-status-value"),
                ],
                className="rw-status-block",
            ),
            html.Div(
                [
                    html.Button(
                        "Save Draft",
                        id="rw-save-button",
                        className="btn-astra",
                        n_clicks=0,
                    ),
                    html.Button(
                        "Submit Final Report",
                        id="rw-submit-button",
                        className="btn-astra btn-primary-astra",
                        n_clicks=0,
                    ),
                ],
                style={"display": "flex", "gap": "10px"},
            ),
        ],
        className="rw-submit-bar",
    )


def _scorecard_placeholder() -> html.Div:
    """Empty scorecard slot — populated after submission."""
    return html.Div(id="rw-scorecard", style={"display": "none"})


def layout(session_id: str, report_type: str = None):
    """Render the report writer for a given session and report type."""
    return html.Div(
        [
            # State
            dcc.Store(id="rw-session-id", data=session_id),
            dcc.Store(id="rw-report-type", data=report_type or "incident"),
            dcc.Store(id="rw-template", data={}),     # populated by callback
            dcc.Store(id="rw-content",  data={}),     # current draft content
            dcc.Store(id="rw-facts",    data={}),     # session facts
            dcc.Store(id="rw-submitted", data=False), # has been submitted?
            # Hidden tick for autosave
            dcc.Interval(id="rw-autosave-tick", interval=12000, n_intervals=0, disabled=False),

            # Header
            html.Div(
                [
                    html.Div(
                        [
                            html.H2("Write Your Report", className="page-heading"),
                            html.Div(id="rw-session-info", className="session-info-row"),
                        ],
                    ),
                    _submit_bar(),
                ],
                className="live-header",
            ),

            # Body — two columns
            html.Div(
                [
                    html.Div(
                        id="rw-sections-container",
                        className="rw-main-col",
                    ),
                    html.Div(
                        [_facts_panel()],
                        className="rw-side-col",
                    ),
                ],
                className="rw-grid",
            ),

            _scorecard_placeholder(),
        ],
    )
