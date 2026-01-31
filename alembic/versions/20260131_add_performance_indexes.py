"""Add performance indexes and risk count caching

Revision ID: 20260131_0001
Revises: 20260129_add_project_number
Create Date: 2026-01-31 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260131_0001'
down_revision = '20260129_add_project_number'
branch_labels = None
depends_on = None


def upgrade():
    # Add risk count cache columns
    op.add_column('threat_assessments', sa.Column('critical_count', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('threat_assessments', sa.Column('high_count', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('threat_assessments', sa.Column('medium_count', sa.Integer(), nullable=True, server_default='0'))
    
    # Add indexes for frequently filtered columns
    op.create_index('ix_threat_assessments_framework', 'threat_assessments', ['framework'])
    op.create_index('ix_threat_assessments_risk_type', 'threat_assessments', ['risk_type'])
    op.create_index('ix_threat_assessments_status', 'threat_assessments', ['status'])
    
    # Update existing records with computed risk counts
    # Note: This will be slow for large datasets, consider running offline
    connection = op.get_bind()
    connection.execute(sa.text("""
        UPDATE threat_assessments 
        SET 
            critical_count = (LENGTH(UPPER(assessment_report)) - LENGTH(REPLACE(UPPER(assessment_report), 'CRITICAL', ''))) / LENGTH('CRITICAL'),
            high_count = (LENGTH(UPPER(assessment_report)) - LENGTH(REPLACE(UPPER(assessment_report), 'HIGH', ''))) / LENGTH('HIGH'),
            medium_count = (LENGTH(UPPER(assessment_report)) - LENGTH(REPLACE(UPPER(assessment_report), 'MEDIUM', ''))) / LENGTH('MEDIUM')
        WHERE assessment_report IS NOT NULL
    """))


def downgrade():
    # Remove indexes
    op.drop_index('ix_threat_assessments_status', 'threat_assessments')
    op.drop_index('ix_threat_assessments_risk_type', 'threat_assessments')
    op.drop_index('ix_threat_assessments_framework', 'threat_assessments')
    
    # Remove columns
    op.drop_column('threat_assessments', 'medium_count')
    op.drop_column('threat_assessments', 'high_count')
    op.drop_column('threat_assessments', 'critical_count')
