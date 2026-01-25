"""initial schema

Revision ID: 20260125_0001
Revises: 
Create Date: 2026-01-25 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20260125_0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Organizations
    op.create_table(
        'organizations',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=100), nullable=False),
        sa.Column('domain', sa.String(length=255)),
        sa.Column('saml_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('saml_metadata_url', sa.Text()),
        sa.Column('saml_entity_id', sa.String(length=255)),
        sa.Column('saml_sso_url', sa.String(length=512)),
        sa.Column('saml_x509_cert', sa.Text()),
        sa.Column('max_users', sa.Integer(), server_default='10', nullable=False),
        sa.Column('max_api_calls_per_month', sa.Integer(), server_default='1000', nullable=False),
        sa.Column('storage_limit_gb', sa.Float(), server_default='10.0', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime()),
        sa.UniqueConstraint('name'),
        sa.UniqueConstraint('slug')
    )
    op.create_index('ix_organizations_id', 'organizations', ['id'])
    op.create_index('ix_organizations_name', 'organizations', ['name'])
    op.create_index('ix_organizations_slug', 'organizations', ['slug'])

    # Users
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('full_name', sa.String(length=255)),
        sa.Column('password_hash', sa.String(length=255)),
        sa.Column('saml_name_id', sa.String(length=255)),
        sa.Column('role', sa.String(length=50), server_default='user', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('is_org_admin', sa.Boolean(), server_default=sa.text('false'), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('last_login', sa.DateTime()),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id']),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('username')
    )
    op.create_index('ix_users_id', 'users', ['id'])
    op.create_index('ix_users_email', 'users', ['email'])
    op.create_index('ix_users_username', 'users', ['username'])
    op.create_index('ix_users_organization_id', 'users', ['organization_id'])

    # API Keys
    op.create_table(
        'api_keys',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('key_prefix', sa.String(length=20), nullable=False),
        sa.Column('key_hash', sa.String(length=255), nullable=False),
        sa.Column('scopes', postgresql.JSON(astext_type=sa.Text())),
        sa.Column('rate_limit', sa.Integer(), server_default='100', nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('expires_at', sa.DateTime()),
        sa.Column('last_used_at', sa.DateTime()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.UniqueConstraint('key_hash')
    )
    op.create_index('ix_api_keys_id', 'api_keys', ['id'])
    op.create_index('ix_api_keys_key_prefix', 'api_keys', ['key_prefix'])
    op.create_index('ix_api_keys_key_hash', 'api_keys', ['key_hash'])
    op.create_index('ix_api_keys_organization_id', 'api_keys', ['organization_id'])
    op.create_index('ix_api_keys_user_id', 'api_keys', ['user_id'])

    # Audit Logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer()),
        sa.Column('user_email', sa.String(length=255)),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=50)),
        sa.Column('resource_id', sa.Integer()),
        sa.Column('description', sa.Text()),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text())),
        sa.Column('status', sa.String(length=20), server_default='success', nullable=False),
        sa.Column('error_message', sa.Text()),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('ip_address', sa.String(length=45)),
        sa.Column('user_agent', sa.String(length=512)),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'])
    )
    op.create_index('ix_audit_logs_id', 'audit_logs', ['id'])
    op.create_index('ix_audit_logs_timestamp', 'audit_logs', ['timestamp'])
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])

    # Threat Assessments
    op.create_table(
        'threat_assessments',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('project_name', sa.String(length=255), nullable=False),
        sa.Column('framework', sa.String(length=50), nullable=False),
        sa.Column('risk_type', sa.String(length=50)),
        sa.Column('system_description', sa.Text()),
        sa.Column('assessment_report', sa.Text()),
        sa.Column('report_html', sa.Text()),
        sa.Column('report_metadata', postgresql.JSON(astext_type=sa.Text())),
        sa.Column('uploaded_files', postgresql.JSON(astext_type=sa.Text())),
        sa.Column('status', sa.String(length=20), server_default='completed', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime()),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'])
    )
    op.create_index('ix_threat_assessments_id', 'threat_assessments', ['id'])
    op.create_index('ix_threat_assessments_organization_id', 'threat_assessments', ['organization_id'])
    op.create_index('ix_threat_assessments_user_id', 'threat_assessments', ['user_id'])
    op.create_index('ix_threat_assessments_created_at', 'threat_assessments', ['created_at'])

    # Usage Stats
    op.create_table(
        'usage_stats',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('period_start', sa.DateTime(), nullable=False),
        sa.Column('period_end', sa.DateTime(), nullable=False),
        sa.Column('period_type', sa.String(length=20), server_default='daily', nullable=False),
        sa.Column('total_assessments', sa.Integer(), server_default='0', nullable=False),
        sa.Column('total_api_calls', sa.Integer(), server_default='0', nullable=False),
        sa.Column('total_users', sa.Integer(), server_default='0', nullable=False),
        sa.Column('active_users', sa.Integer(), server_default='0', nullable=False),
        sa.Column('storage_used_gb', sa.Float(), server_default='0', nullable=False),
        sa.Column('assessments_by_framework', postgresql.JSON(astext_type=sa.Text())),
        sa.Column('assessments_by_risk_type', postgresql.JSON(astext_type=sa.Text())),
        sa.Column('api_calls_by_endpoint', postgresql.JSON(astext_type=sa.Text())),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'])
    )
    op.create_index('ix_usage_stats_id', 'usage_stats', ['id'])
    op.create_index('ix_usage_stats_organization_id', 'usage_stats', ['organization_id'])
    op.create_index('ix_usage_stats_period_start', 'usage_stats', ['period_start'])



def downgrade() -> None:
    op.drop_table('usage_stats')
    op.drop_table('threat_assessments')
    op.drop_table('audit_logs')
    op.drop_table('api_keys')
    op.drop_table('users')
    op.drop_table('organizations')
