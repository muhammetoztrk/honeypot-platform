from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from io import BytesIO
from datetime import datetime, timedelta
from typing import List, Dict
from collections import Counter, defaultdict


def generate_pdf_report(events: List[Dict], iocs: List[Dict], stats: Dict) -> BytesIO:
    """Generate a comprehensive PDF security report"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    
    # Container for the 'Flowable' objects
    elements = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER,
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=12,
    )
    
    # Title
    elements.append(Paragraph("Honeypot Security Report", title_style))
    elements.append(Spacer(1, 0.2*inch))
    
    # Report metadata
    metadata = [
        ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ['Report Period:', 'Last 24 Hours'],
        ['Total Events:', str(len(events))],
        ['Total IOCs:', str(len(iocs))],
    ]
    
    metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#34495e')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
    ]))
    elements.append(metadata_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Executive Summary with Analysis
    elements.append(Paragraph("Executive Summary", heading_style))
    
    # Analyze events
    event_types = Counter([e.get('event_type', 'unknown') for e in events])
    high_risk_iocs = [i for i in iocs if i.get('score', 0) > 70]
    medium_risk_iocs = [i for i in iocs if 40 < i.get('score', 0) <= 70]
    
    # Analyze attack patterns
    ip_activity = Counter([e.get('src_ip', 'unknown') for e in events])
    top_attacker_ips = ip_activity.most_common(5)
    
    # Calculate risk level
    total_risk_score = sum(i.get('score', 0) for i in iocs)
    avg_risk_score = total_risk_score / len(iocs) if iocs else 0
    risk_level = "CRITICAL" if avg_risk_score > 70 else "HIGH" if avg_risk_score > 50 else "MEDIUM" if avg_risk_score > 30 else "LOW"
    
    summary_text = f"""
    <b>Risk Assessment:</b> <font color="{'#e74c3c' if risk_level in ['CRITICAL', 'HIGH'] else '#f39c12'}">{risk_level}</font><br/><br/>
    
    This security report provides a comprehensive analysis of honeypot activity. The platform detected <b>{len(events)}</b> security events 
    and identified <b>{len(iocs)}</b> indicators of compromise over the reporting period. <b>{len(high_risk_iocs)}</b> high-risk IOCs 
    (score > 70) and <b>{len(medium_risk_iocs)}</b> medium-risk IOCs (score 40-70) were identified.<br/><br/>
    
    <b>Key Findings:</b><br/>
    • Average IOC Risk Score: <b>{avg_risk_score:.1f}/100</b><br/>
    • Most active attack type: <b>{event_types.most_common(1)[0][0] if event_types else 'N/A'}</b> ({event_types.most_common(1)[0][1] if event_types else 0} events)<br/>
    • Top attacking IP: <b>{top_attacker_ips[0][0] if top_attacker_ips else 'N/A'}</b> ({top_attacker_ips[0][1] if top_attacker_ips else 0} events)<br/>
    • Active honeypots: <b>{stats.get('honeypots', 0)}</b>, Online nodes: <b>{stats.get('nodes', 0)}</b>
    """
    elements.append(Paragraph(summary_text, styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))
    
    # Threat Analysis Section
    elements.append(Paragraph("Threat Analysis & Risk Assessment", heading_style))
    
    # Analyze why scores are high
    analysis_text = f"""
    <b>Why These Scores Were Assigned:</b><br/><br/>
    
    IOC scores are calculated based on multiple factors including frequency of appearance, attack patterns, and threat intelligence data.
    High scores (70+) indicate repeated malicious activity, suspicious commands, or known threat indicators. Medium scores (40-70) 
    suggest suspicious but not definitively malicious behavior. Low scores (0-40) represent initial reconnaissance or low-risk probes.<br/><br/>
    
    <b>Attack Pattern Analysis:</b><br/>
    """
    
    # Analyze attack patterns
    if events:
        ssh_events = [e for e in events if e.get('event_type') == 'ssh_connection']
        web_events = [e for e in events if e.get('event_type') == 'web_request']
        
        if ssh_events:
            # Analyze SSH commands
            all_commands = []
            for e in ssh_events:
                payload = e.get('payload', {})
                commands = payload.get('commands', [])
                all_commands.extend(commands)
            
            dangerous_commands = [c for c in all_commands if any(keyword in c.lower() for keyword in ['rm', 'delete', 'drop', 'exec', 'wget', 'curl', 'bash'])]
            
            analysis_text += f"""
            • <b>SSH Attacks:</b> {len(ssh_events)} SSH connection attempts detected. {len(dangerous_commands)} potentially dangerous commands 
            identified (file deletion, code execution, data exfiltration attempts).<br/>
            """
        
        if web_events:
            # Analyze web requests
            login_attempts = [e for e in web_events if e.get('payload', {}).get('method') == 'POST']
            admin_access = [e for e in web_events if '/admin' in str(e.get('payload', {}).get('path', '')).lower()]
            
            analysis_text += f"""
            • <b>Web Attacks:</b> {len(web_events)} web requests detected. {len(login_attempts)} login attempts and 
            {len(admin_access)} admin panel access attempts identified.<br/>
            """
    
    # IP analysis
    if top_attacker_ips:
        analysis_text += f"""
        • <b>Top Attacker IPs:</b> {', '.join([f"{ip} ({count}x)" for ip, count in top_attacker_ips[:3]])}<br/>
        """
    
    analysis_text += """
    <br/><b>Risk Factors Identified:</b><br/>
    • Repeated connection attempts from same IPs indicate automated scanning<br/>
    • Suspicious command execution attempts suggest exploitation attempts<br/>
    • Admin panel and login page targeting indicates credential harvesting attempts<br/>
    • High-frequency attacks suggest botnet or automated attack infrastructure
    """
    
    elements.append(Paragraph(analysis_text, styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))
    
    # Statistics Overview
    elements.append(Paragraph("Statistics Overview", heading_style))
    
    # Event type breakdown
    event_types_dict = {}
    for event in events:
        event_type = event.get('event_type', 'unknown')
        event_types_dict[event_type] = event_types_dict.get(event_type, 0) + 1
    
    stats_data = [['Metric', 'Count', 'Analysis']]
    stats_data.append(['Total Events', str(len(events)), 'All security events captured'])
    stats_data.append(['Total IOCs', str(len(iocs)), f'{len(high_risk_iocs)} high-risk, {len(medium_risk_iocs)} medium-risk'])
    stats_data.append(['Active Honeypots', str(stats.get('honeypots', 0)), 'Currently monitoring'])
    stats_data.append(['Online Nodes', str(stats.get('nodes', 0)), 'Infrastructure status'])
    
    for event_type, count in event_types_dict.items():
        percentage = (count / len(events) * 100) if events else 0
        stats_data.append([f'Events: {event_type}', str(count), f'{percentage:.1f}% of total'])
    
    stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
    ]))
    elements.append(stats_table)
    elements.append(PageBreak())
    
    # Top IOCs
    if iocs:
        elements.append(Paragraph("Top Indicators of Compromise", heading_style))
        ioc_data = [['Type', 'Value', 'Score', 'Seen Count', 'First Seen']]
        
        # Sort by score
        sorted_iocs = sorted(iocs, key=lambda x: x.get('score', 0), reverse=True)[:20]
        
        for ioc in sorted_iocs:
            ioc_data.append([
                ioc.get('ioc_type', 'N/A'),
                ioc.get('value', 'N/A')[:50],  # Truncate long values
                str(ioc.get('score', 0)),
                str(ioc.get('seen_count', 0)),
                datetime.fromisoformat(str(ioc.get('first_seen', ''))).strftime('%Y-%m-%d %H:%M') if ioc.get('first_seen') else 'N/A',
            ])
        
        ioc_data_with_reason = [['Type', 'Value', 'Score', 'Seen', 'Risk Explanation']]
        
        for ioc in sorted_iocs:
            score = ioc.get('score', 0)
            seen_count = ioc.get('seen_count', 0)
            ioc_type = ioc.get('ioc_type', 'N/A')
            
            # Explain why this score
            if score > 70:
                reason = f"High risk: {seen_count}x seen, repeated malicious activity"
            elif score > 40:
                reason = f"Medium risk: {seen_count}x seen, suspicious patterns"
            else:
                reason = f"Low risk: {seen_count}x seen, initial probe"
            
            if ioc_type == 'ip' and seen_count > 5:
                reason += ", frequent attacker"
            if ioc_type == 'credential':
                reason += ", credential harvesting attempt"
            
            ioc_data_with_reason.append([
                ioc_type,
                ioc.get('value', 'N/A')[:40],
                str(score),
                str(seen_count),
                reason[:50],
            ])
        
        ioc_table = Table(ioc_data_with_reason, colWidths=[0.7*inch, 1.8*inch, 0.6*inch, 0.6*inch, 2.3*inch])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (2, 1), (2, -1), 'CENTER'),
            ('ALIGN', (3, 1), (3, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))
        elements.append(ioc_table)
        elements.append(PageBreak())
    
    # Recommendations Section
    elements.append(Paragraph("Security Recommendations", heading_style))
    
    recommendations = []
    if len(high_risk_iocs) > 0:
        recommendations.append(f"• <b>Immediate Action Required:</b> {len(high_risk_iocs)} high-risk IOCs detected. Consider blocking these IPs and investigating their origin.")
    
    if top_attacker_ips and top_attacker_ips[0][1] > 10:
        recommendations.append(f"• <b>Automated Attack Detected:</b> IP {top_attacker_ips[0][0]} has made {top_attacker_ips[0][1]} connection attempts. This indicates automated scanning/botnet activity.")
    
    if any('ssh_connection' in str(e.get('event_type')) for e in events):
        recommendations.append("• <b>SSH Security:</b> Multiple SSH connection attempts detected. Ensure strong authentication and consider implementing fail2ban.")
    
    if any('web_request' in str(e.get('event_type')) for e in events):
        recommendations.append("• <b>Web Security:</b> Web honeypot activity detected. Monitor for credential harvesting attempts and ensure production systems use different credentials.")
    
    if not recommendations:
        recommendations.append("• Continue monitoring honeypot activity for emerging threats.")
        recommendations.append("• Review IOC scores regularly and adjust thresholds as needed.")
    
    rec_text = "<br/>".join(recommendations)
    elements.append(Paragraph(rec_text, styles['Normal']))
    elements.append(Spacer(1, 0.3*inch))
    
    # Recent Events with Analysis
    if events:
        elements.append(Paragraph("Detailed Event Analysis", heading_style))
        
        # Group events by type and analyze
        event_analysis_text = f"""
        <b>Event Breakdown by Type:</b><br/>
        """
        for event_type, count in event_types_dict.items():
            percentage = (count / len(events) * 100) if events else 0
            event_analysis_text += f"• <b>{event_type}:</b> {count} events ({percentage:.1f}% of total)<br/>"
        
        elements.append(Paragraph(event_analysis_text, styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        event_data = [['Time', 'Source IP', 'Type', 'Activity', 'Risk']]
        
        # Get most recent events
        recent_events = sorted(events, key=lambda x: x.get('ts', ''), reverse=True)[:25]
        
        for event in recent_events:
            ts = event.get('ts', '')
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M')
                except:
                    ts = str(ts)[:16]
            else:
                ts = str(ts)[:16]
            
            payload = event.get('payload', {})
            event_type = event.get('event_type', 'N/A')
            
            # Analyze activity
            activity = "Connection attempt"
            risk = "Low"
            
            if event_type == 'ssh_connection':
                commands = payload.get('commands', [])
                if commands:
                    dangerous = any(kw in str(commands).lower() for kw in ['rm', 'delete', 'exec', 'wget'])
                    activity = f"{len(commands)} commands" + (" (dangerous)" if dangerous else "")
                    risk = "High" if dangerous else "Medium"
            elif event_type == 'web_request':
                method = payload.get('method', 'GET')
                path = payload.get('path', '')
                if method == 'POST':
                    activity = f"Login attempt to {path}"
                    risk = "Medium"
                elif '/admin' in path.lower():
                    activity = f"Admin panel access: {path}"
                    risk = "Medium"
                else:
                    activity = f"{method} {path}"
            
            # Check if IP is frequent attacker
            ip = event.get('src_ip', 'N/A')
            if ip in dict(top_attacker_ips) and dict(top_attacker_ips)[ip] > 5:
                risk = "High"
            
            event_data.append([
                ts,
                ip,
                event_type,
                activity[:40],
                risk,
            ])
        
        event_table = Table(event_data, colWidths=[1*inch, 1*inch, 0.9*inch, 2.1*inch, 0.8*inch])
        event_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#27ae60')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (4, 1), (4, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))
        elements.append(event_table)
    
    # Footer
    elements.append(Spacer(1, 0.3*inch))
    footer_text = f"<i>Report generated by Honeypot Deception Platform on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
    elements.append(Paragraph(footer_text, styles['Italic']))
    
    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return buffer

