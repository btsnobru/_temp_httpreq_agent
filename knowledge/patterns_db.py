
import sqlite3
import asyncio
import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

class PatternsDatabase:
    """
    Database for storing and retrieving vulnerability patterns, target intelligence,
    and learning data for the DesyncHunter system.
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Targets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                domain TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scanned TIMESTAMP,
                priority INTEGER DEFAULT 1,
                findings_count INTEGER DEFAULT 0,
                success_rate REAL DEFAULT 0.0,
                infrastructure_fingerprint TEXT,
                notes TEXT
            )
        ''')
        
        # Findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT,
                technique TEXT,
                confidence REAL,
                status TEXT, -- detected, validated, exploited, false_positive
                evidence TEXT, -- JSON blob
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                validation_data TEXT,
                exploit_data TEXT,
                bounty_reported BOOLEAN DEFAULT FALSE,
                bounty_amount REAL DEFAULT 0.0,
                FOREIGN KEY (target_url) REFERENCES targets(url)
            )
        ''')
        
        # Patterns table for successful attack vectors
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique TEXT,
                infrastructure_type TEXT,
                success_rate REAL,
                payload_template TEXT,
                conditions TEXT, -- JSON blob
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                usage_count INTEGER DEFAULT 0
            )
        ''')
        
        # Intelligence table for target-specific insights
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS target_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT,
                intelligence_type TEXT, -- fingerprint, vulnerability, bypass_method
                data TEXT, -- JSON blob
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (target_url) REFERENCES targets(url)
            )
        ''')
        
        # Performance metrics
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                targets_scanned INTEGER,
                findings_detected INTEGER,
                findings_validated INTEGER,
                findings_exploited INTEGER,
                total_cost REAL,
                execution_time REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Database initialized at {self.db_path}")
    
    async def get_target_priority(self, url: str) -> int:
        """Get target priority based on historical data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT priority, findings_count, success_rate
            FROM targets 
            WHERE url = ?
        ''', (url,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            priority, findings_count, success_rate = result
            # Boost priority based on historical success
            if success_rate > 0.5 and findings_count > 0:
                priority += 2
            elif findings_count > 0:
                priority += 1
        else:
            # New target, default priority
            priority = 1
        
        return min(priority, 5)  # Cap at 5
    
    async def store_target_info(self, url: str, infrastructure_data: Dict[str, Any]) -> None:
        """Store target information and infrastructure fingerprint."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        domain = url.split('/')[2] if '//' in url else url
        infrastructure_json = json.dumps(infrastructure_data)
        
        cursor.execute('''
            INSERT OR REPLACE INTO targets 
            (url, domain, last_scanned, infrastructure_fingerprint)
            VALUES (?, ?, CURRENT_TIMESTAMP, ?)
        ''', (url, domain, infrastructure_json))
        
        conn.commit()
        conn.close()
        
        self.logger.debug(f"Stored target info for {url}")
    
    async def store_finding(self, finding_data: Dict[str, Any]) -> int:
        """Store a vulnerability finding."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO findings 
            (target_url, technique, confidence, status, evidence)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            finding_data.get('target_url'),
            finding_data.get('technique'),
            finding_data.get('confidence', 0.0),
            'detected',
            json.dumps(finding_data.get('evidence', {}))
        ))
        
        finding_id = cursor.lastrowid
        
        # Update target findings count
        cursor.execute('''
            UPDATE targets 
            SET findings_count = findings_count + 1
            WHERE url = ?
        ''', (finding_data.get('target_url'),))
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Stored finding {finding_id} for {finding_data.get('target_url')}")
        return finding_id
    
    async def update_finding_status(self, finding_id: int, status: str, additional_data: Optional[Dict] = None) -> None:
        """Update finding status (validated, exploited, false_positive)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        update_fields = ['status = ?', 'updated_at = CURRENT_TIMESTAMP']
        params = [status]
        
        if additional_data:
            if status == 'validated':
                update_fields.append('validation_data = ?')
                params.append(json.dumps(additional_data))
            elif status == 'exploited':
                update_fields.append('exploit_data = ?')
                params.append(json.dumps(additional_data))
        
        params.append(finding_id)
        
        cursor.execute(f'''
            UPDATE findings 
            SET {', '.join(update_fields)}
            WHERE id = ?
        ''', params)
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Updated finding {finding_id} status to {status}")
    
    async def get_successful_patterns(self, technique: str, infrastructure_type: str = None) -> List[Dict[str, Any]]:
        """Get successful attack patterns for a technique and infrastructure."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if infrastructure_type:
            cursor.execute('''
                SELECT technique, infrastructure_type, payload_template, conditions, success_rate
                FROM attack_patterns
                WHERE technique = ? AND infrastructure_type = ?
                ORDER BY success_rate DESC, usage_count DESC
            ''', (technique, infrastructure_type))
        else:
            cursor.execute('''
                SELECT technique, infrastructure_type, payload_template, conditions, success_rate
                FROM attack_patterns
                WHERE technique = ?
                ORDER BY success_rate DESC, usage_count DESC
            ''', (technique,))
        
        results = cursor.fetchall()
        conn.close()
        
        patterns = []
        for row in results:
            patterns.append({
                'technique': row[0],
                'infrastructure_type': row[1],
                'payload_template': row[2],
                'conditions': json.loads(row[3]) if row[3] else {},
                'success_rate': row[4]
            })
        
        return patterns
    
    async def store_successful_pattern(self, pattern_data: Dict[str, Any]) -> None:
        """Store a successful attack pattern for future use."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO attack_patterns
            (technique, infrastructure_type, payload_template, conditions, success_rate, usage_count)
            VALUES (?, ?, ?, ?, ?, 
                COALESCE((SELECT usage_count FROM attack_patterns 
                         WHERE technique = ? AND infrastructure_type = ?), 0) + 1)
        ''', (
            pattern_data.get('technique'),
            pattern_data.get('infrastructure_type'),
            pattern_data.get('payload_template'),
            json.dumps(pattern_data.get('conditions', {})),
            pattern_data.get('success_rate', 1.0),
            pattern_data.get('technique'),
            pattern_data.get('infrastructure_type')
        ))
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Stored successful pattern for {pattern_data.get('technique')}")
    
    async def get_target_intelligence(self, url: str, intelligence_type: str = None) -> List[Dict[str, Any]]:
        """Get stored intelligence for a target."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if intelligence_type:
            cursor.execute('''
                SELECT intelligence_type, data, confidence, created_at
                FROM target_intelligence
                WHERE target_url = ? AND intelligence_type = ?
                AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                ORDER BY confidence DESC, created_at DESC
            ''', (url, intelligence_type))
        else:
            cursor.execute('''
                SELECT intelligence_type, data, confidence, created_at
                FROM target_intelligence
                WHERE target_url = ?
                AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                ORDER BY confidence DESC, created_at DESC
            ''', (url,))
        
        results = cursor.fetchall()
        conn.close()
        
        intelligence = []
        for row in results:
            intelligence.append({
                'type': row[0],
                'data': json.loads(row[1]) if row[1] else {},
                'confidence': row[2],
                'created_at': row[3]
            })
        
        return intelligence
    
    async def store_target_intelligence(self, url: str, intelligence_type: str, data: Dict[str, Any], 
                                      confidence: float, expires_hours: int = None) -> None:
        """Store target-specific intelligence."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        expires_at = None
        if expires_hours:
            expires_at = datetime.now() + timedelta(hours=expires_hours)
        
        cursor.execute('''
            INSERT OR REPLACE INTO target_intelligence
            (target_url, intelligence_type, data, confidence, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (url, intelligence_type, json.dumps(data), confidence, expires_at))
        
        conn.commit()
        conn.close()
        
        self.logger.debug(f"Stored {intelligence_type} intelligence for {url}")
    
    async def get_performance_metrics(self, days: int = 30) -> Dict[str, Any]:
        """Get performance metrics for the last N days."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since_date = datetime.now() - timedelta(days=days)
        
        cursor.execute('''
            SELECT 
                COUNT(*) as sessions,
                SUM(targets_scanned) as total_targets,
                SUM(findings_detected) as total_findings,
                SUM(findings_validated) as total_validated,
                SUM(findings_exploited) as total_exploited,
                SUM(total_cost) as total_cost,
                AVG(execution_time) as avg_execution_time
            FROM performance_metrics
            WHERE created_at >= ?
        ''', (since_date,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'sessions': result[0] or 0,
                'total_targets': result[1] or 0,
                'total_findings': result[2] or 0,
                'total_validated': result[3] or 0,
                'total_exploited': result[4] or 0,
                'total_cost': result[5] or 0.0,
                'avg_execution_time': result[6] or 0.0,
                'success_rate': (result[4] or 0) / max(result[1] or 1, 1),
                'validation_rate': (result[3] or 0) / max(result[2] or 1, 1)
            }
        else:
            return {
                'sessions': 0,
                'total_targets': 0,
                'total_findings': 0,
                'total_validated': 0,
                'total_exploited': 0,
                'total_cost': 0.0,
                'avg_execution_time': 0.0,
                'success_rate': 0.0,
                'validation_rate': 0.0
            }
    
    async def store_session_metrics(self, session_data: Dict[str, Any]) -> None:
        """Store performance metrics for a session."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO performance_metrics
            (session_id, targets_scanned, findings_detected, findings_validated, 
             findings_exploited, total_cost, execution_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_data.get('session_id'),
            session_data.get('targets_scanned', 0),
            session_data.get('findings_detected', 0),
            session_data.get('findings_validated', 0),
            session_data.get('findings_exploited', 0),
            session_data.get('total_cost', 0.0),
            session_data.get('execution_time', 0.0)
        ))
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Stored session metrics for {session_data.get('session_id')}")
    
    async def cleanup_old_data(self, days: int = 365) -> None:
        """Clean up old data beyond retention period."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        # Clean expired intelligence
        cursor.execute('''
            DELETE FROM target_intelligence 
            WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP
        ''')
        
        # Clean old performance metrics
        cursor.execute('''
            DELETE FROM performance_metrics 
            WHERE created_at < ?
        ''', (cutoff_date,))
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Cleaned up data older than {days} days")
