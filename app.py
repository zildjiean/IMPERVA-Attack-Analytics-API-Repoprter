#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Imperva Attack Analytics Web Frontend
Flask web application for generating Attack Analytics reports
"""

import os
import json
from datetime import datetime, date
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import tempfile
import threading
import time
from aa_report import generate_report

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# Configuration
UPLOAD_FOLDER = 'reports'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create reports directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Store for tracking report generation status
report_status = {}
report_lock = threading.Lock()

@app.route('/')
def index():
    """Main page with form for generating reports"""
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    """Generate report endpoint"""
    try:
        # Get form data
        api_id = request.form.get('api_id')
        api_key = request.form.get('api_key')
        caid = request.form.get('caid')
        date_str = request.form.get('date')
        end_date_str = request.form.get('end_date')
        tz = request.form.get('tz', 'Asia/Bangkok')
        granularity = request.form.get('granularity', 'hour')
        severity_filter = request.form.get('severity_filter')
        breakdown_limit = int(request.form.get('breakdown_limit', 10))
        breakdown_hosts = request.form.get('breakdown_hosts')
        mask_ips = request.form.get('mask_ips') == 'on'
        mask_cidr = request.form.get('mask_cidr')
        theme = request.form.get('theme', 'dark')
        
        # Validate required fields
        if not all([api_id, api_key, caid, date_str]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Convert caid to int
        try:
            caid = int(caid)
        except ValueError:
            return jsonify({'error': 'Invalid CAID format'}), 400
        
        # Convert mask_cidr to int if provided
        if mask_cidr:
            try:
                mask_cidr = int(mask_cidr)
            except ValueError:
                mask_cidr = None
        
        # Generate unique task ID
        task_id = f"{caid}_{date_str}_{int(time.time())}"
        
        # Initialize status
        with report_lock:
            report_status[task_id] = {
                'status': 'processing',
                'progress': 0,
                'message': 'Starting report generation...',
                'created_at': datetime.now().isoformat(),
                'caid': caid,
                'date': date_str,
                'timezone': tz,
                'theme': theme
            }
        
        # Start background task
        def generate_report_task():
            try:
                with report_lock:
                    report_status[task_id]['message'] = 'Fetching incidents...'
                    report_status[task_id]['progress'] = 25
                
                html_content, filename, error = generate_report(
                    api_id=api_id,
                    api_key=api_key,
                    caid=caid,
                    date_str=date_str,
                    end_date_str=end_date_str if end_date_str else None,
                    tz=tz,
                    granularity=granularity,
                    severity_filter=severity_filter if severity_filter else None,
                    breakdown_limit=breakdown_limit,
                    breakdown_hosts=breakdown_hosts if breakdown_hosts else None,
                    mask_ips=mask_ips,
                    mask_cidr=mask_cidr,
                    theme=theme
                )
                
                if error:
                    with report_lock:
                        report_status[task_id].update({
                            'status': 'error',
                            'progress': 0,
                            'message': error
                        })
                    return
                
                # Save report to file
                report_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                with report_lock:
                    report_status[task_id].update({
                        'status': 'completed',
                        'progress': 100,
                        'message': 'Report generated successfully',
                        'filename': filename,
                        'file_path': report_path
                    })
                    
            except Exception as e:
                with report_lock:
                    report_status[task_id].update({
                        'status': 'error',
                        'progress': 0,
                        'message': f'Error: {str(e)}'
                    })
        
        # Start the background thread
        thread = threading.Thread(target=generate_report_task)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'task_id': task_id,
            'status': 'processing',
            'message': 'Report generation started'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/status/<task_id>')
def get_status(task_id):
    """Get report generation status"""
    with report_lock:
        status = report_status.get(task_id)
    
    if not status:
        return jsonify({'error': 'Task not found'}), 404
    
    return jsonify(status)

@app.route('/download/<task_id>')
def download_report(task_id):
    """Download generated report"""
    with report_lock:
        status = report_status.get(task_id)
    
    if not status or status['status'] != 'completed':
        return jsonify({'error': 'Report not ready'}), 404
    
    file_path = status.get('file_path')
    filename = status.get('filename')
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'Report file not found'}), 404
    
    return send_file(file_path, as_attachment=True, download_name=filename)

@app.route('/reports')
def list_reports():
    """Show reports page"""
    return render_template('reports.html')

@app.route('/api/reports')
def api_list_reports():
    """API endpoint to get reports data as JSON"""
    reports = []
    
    with report_lock:
        for task_id, status in report_status.items():
            reports.append({
                'task_id': task_id,
                'filename': status.get('filename'),
                'created_at': status.get('created_at'),
                'message': status.get('message'),
                'status': status.get('status'),
                'caid': status.get('caid'),
                'date': status.get('date'),
                'timezone': status.get('timezone'),
                'theme': status.get('theme')
            })
    
    # Sort by creation time (newest first)
    reports.sort(key=lambda x: x.get('created_at', 0), reverse=True)
    
    return jsonify({'reports': reports})

@app.route('/view/<task_id>')
def view_report(task_id):
    """View report in browser"""
    with report_lock:
        status = report_status.get(task_id)
    
    if not status or status['status'] != 'completed':
        flash('Report not found or not ready', 'error')
        return redirect(url_for('list_reports'))
    
    file_path = status.get('file_path')
    
    if not file_path or not os.path.exists(file_path):
        flash('Report file not found', 'error')
        return redirect(url_for('list_reports'))
    
    # Read and return the HTML content directly
    with open(file_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    return html_content

@app.route('/delete/<task_id>', methods=['DELETE'])
def delete_report(task_id):
    """Delete report and its file"""
    try:
        with report_lock:
            status = report_status.get(task_id)
            
            if not status:
                return jsonify({'error': 'Report not found'}), 404
            
            # Delete the file if it exists
            file_path = status.get('file_path')
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
            
            # Remove from status tracking
            del report_status[task_id]
        
        return jsonify({
            'success': True,
            'message': 'Report deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large'}), 413

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Check if running in Docker or production environment
    import os
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)