"use client";

import React, { useMemo } from "react";

interface MarkdownRendererProps {
  content: string;
}

export default function MarkdownRenderer({ content }: MarkdownRendererProps) {
  const renderedElements = useMemo(() => {
    if (!content) return null;

    const lines = content.split("\n");
    const elements: React.ReactNode[] = [];
    let inCodeBlock = false;
    let codeBlockContent: string[] = [];
    let codeBlockLang = "";
    let tableRows: string[][] = [];
    let inTable = false;

    const flushTable = (key: string) => {
      if (tableRows.length === 0) return;
      const headers = tableRows[0];
      const dataRows = tableRows.slice(1).filter((r) => !r.every((c) => /^[-:| ]+$/.test(c)));

      elements.push(
        <div key={key} style={{ overflowX: "auto", margin: "16px 0" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
            <thead>
              <tr style={{ background: "#111b27", borderBottom: "2px solid #23354b" }}>
                {headers.map((h, i) => (
                  <th key={i} style={{ padding: "8px 12px", color: "#93c5fd", textAlign: "left" }}>
                    {formatInline(h.trim())}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {dataRows.map((row, ri) => (
                <tr key={ri} style={{ borderBottom: "1px solid #1a2738", background: ri % 2 === 0 ? "#0c1420" : "transparent" }}>
                  {row.map((cell, ci) => (
                    <td key={ci} style={{ padding: "8px 12px", color: "#cbd5e1" }}>
                      {formatInline(cell.trim())}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      tableRows = [];
      inTable = false;
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Code blocks
      if (line.trim().startsWith("```")) {
        if (inCodeBlock) {
          elements.push(
            <pre
              key={`code-${i}`}
              style={{
                background: "#050911",
                border: "1px solid #1e2e42",
                borderRadius: "8px",
                padding: "14px",
                overflowX: "auto",
                fontFamily: "monospace",
                fontSize: "12px",
                color: "#62e6a7",
                margin: "12px 0"
              }}
            >
              <code>{codeBlockContent.join("\n")}</code>
            </pre>
          );
          codeBlockContent = [];
          inCodeBlock = false;
        } else {
          if (inTable) flushTable(`table-${i}`);
          inCodeBlock = true;
          codeBlockLang = line.trim().slice(3).trim();
        }
        continue;
      }

      if (inCodeBlock) {
        codeBlockContent.push(line);
        continue;
      }

      // Tables
      if (line.trim().startsWith("|") && line.trim().endsWith("|")) {
        inTable = true;
        const cells = line
          .trim()
          .slice(1, -1)
          .split("|");
        tableRows.push(cells);
        continue;
      } else if (inTable) {
        flushTable(`table-${i}`);
      }

      // Empty lines
      if (!line.trim()) {
        continue;
      }

      // Headings
      if (line.startsWith("# ")) {
        elements.push(
          <h1
            key={`h1-${i}`}
            style={{
              fontSize: "22px",
              fontWeight: 800,
              color: "#62e6a7",
              margin: "24px 0 10px",
              borderBottom: "1px solid #1e334a",
              paddingBottom: "8px"
            }}
          >
            {formatInline(line.slice(2))}
          </h1>
        );
        continue;
      }

      if (line.startsWith("## ")) {
        elements.push(
          <h2
            key={`h2-${i}`}
            style={{
              fontSize: "18px",
              fontWeight: 700,
              color: "#93c5fd",
              margin: "20px 0 8px",
              display: "flex",
              alignItems: "center",
              gap: "8px"
            }}
          >
            {formatInline(line.slice(3))}
          </h2>
        );
        continue;
      }

      if (line.startsWith("### ")) {
        elements.push(
          <h3
            key={`h3-${i}`}
            style={{
              fontSize: "15px",
              fontWeight: 600,
              color: "#f1f5f9",
              margin: "14px 0 6px"
            }}
          >
            {formatInline(line.slice(4))}
          </h3>
        );
        continue;
      }

      // Horizontal Rule
      if (/^(\*\*\*|---|___)$/.test(line.trim())) {
        elements.push(
          <hr
            key={`hr-${i}`}
            style={{ border: "none", borderTop: "1px solid #1c2a3d", margin: "18px 0" }}
          />
        );
        continue;
      }

      // Blockquotes / Callouts
      if (line.startsWith("> ")) {
        elements.push(
          <div
            key={`bq-${i}`}
            style={{
              borderLeft: "3px solid #38bdf8",
              background: "#0c1827",
              padding: "10px 14px",
              borderRadius: "0 8px 8px 0",
              margin: "10px 0",
              fontSize: "13px",
              color: "#cbd5e1"
            }}
          >
            {formatInline(line.slice(2))}
          </div>
        );
        continue;
      }

      // Bullet Lists
      if (line.trim().startsWith("- ") || line.trim().startsWith("* ")) {
        const indent = line.search(/\S/);
        const text = line.trim().slice(2);
        elements.push(
          <div
            key={`li-${i}`}
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "8px",
              marginLeft: `${indent > 0 ? indent * 8 : 8}px`,
              margin: "4px 0",
              fontSize: "13px",
              lineHeight: "1.6",
              color: "#cbd5e1"
            }}
          >
            <span style={{ color: "#4ade80", fontSize: "11px", marginTop: "4px" }}>●</span>
            <div>{formatInline(text)}</div>
          </div>
        );
        continue;
      }

      // Numbered Lists
      const numMatch = line.trim().match(/^(\d+)\.\s+(.*)$/);
      if (numMatch) {
        elements.push(
          <div
            key={`num-${i}`}
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "8px",
              marginLeft: "8px",
              margin: "4px 0",
              fontSize: "13px",
              lineHeight: "1.6",
              color: "#cbd5e1"
            }}
          >
            <span
              style={{
                color: "#60a5fa",
                fontWeight: "bold",
                minWidth: "18px",
                fontSize: "12px"
              }}
            >
              {numMatch[1]}.
            </span>
            <div>{formatInline(numMatch[2])}</div>
          </div>
        );
        continue;
      }

      // Regular Paragraph
      elements.push(
        <p
          key={`p-${i}`}
          style={{
            margin: "8px 0",
            fontSize: "13.5px",
            lineHeight: "1.6",
            color: "#cbd5e1"
          }}
        >
          {formatInline(line)}
        </p>
      );
    }

    if (inTable) flushTable("table-end");

    return elements;
  }, [content]);

  return <div style={{ color: "#e2e8f0", lineHeight: "1.6" }}>{renderedElements}</div>;
}

function formatInline(text: string): React.ReactNode {
  // Parse inline elements: **bold**, `code`, *italic*
  const parts: React.ReactNode[] = [];
  let remaining = text;
  let keyIdx = 0;

  while (remaining.length > 0) {
    // Bold: **text**
    const boldMatch = remaining.match(/\*\*(.*?)\*\*/);
    // Inline code: `code`
    const codeMatch = remaining.match(/`([^`]+)`/);

    const matchIndices = [
      { type: "bold", index: boldMatch ? remaining.indexOf(boldMatch[0]) : -1, match: boldMatch },
      { type: "code", index: codeMatch ? remaining.indexOf(codeMatch[0]) : -1, match: codeMatch }
    ].filter((m) => m.index !== -1);

    if (matchIndices.length === 0) {
      parts.push(remaining);
      break;
    }

    matchIndices.sort((a, b) => a.index - b.index);
    const earliest = matchIndices[0];

    // Push text before match
    if (earliest.index > 0) {
      parts.push(remaining.slice(0, earliest.index));
    }

    if (earliest.type === "bold" && earliest.match) {
      parts.push(
        <strong key={`b-${keyIdx++}`} style={{ color: "#fff", fontWeight: 700 }}>
          {earliest.match[1]}
        </strong>
      );
      remaining = remaining.slice(earliest.index + earliest.match[0].length);
    } else if (earliest.type === "code" && earliest.match) {
      parts.push(
        <code
          key={`c-${keyIdx++}`}
          style={{
            background: "#16202c",
            border: "1px solid #233446",
            color: "#62e6a7",
            padding: "2px 6px",
            borderRadius: "4px",
            fontSize: "12px",
            fontFamily: "monospace"
          }}
        >
          {earliest.match[1]}
        </code>
      );
      remaining = remaining.slice(earliest.index + earliest.match[0].length);
    }
  }

  return <>{parts}</>;
}
