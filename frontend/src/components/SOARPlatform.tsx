import React, { useState, useEffect } from 'react';
import {
  CogIcon,
  PlayIcon,
  PauseIcon,
  StopIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  DocumentTextIcon,
  BoltIcon,
  ArrowPathIcon,
  PlusIcon,
  EyeIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline';

interface Playbook {
  id: string;
  name: string;
  description: string;
  version: string;
  status: 'draft' | 'active' | 'paused' | 'completed' | 'failed' | 'cancelled';
  actions_count: number;
  tags: string[];
  created_by: string;
  created_at: string;
  updated_at: string;
}

interface Execution {
  execution_id: string;
  playbook_id: string;
  incident_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped' | 'requires_approval';
  triggered_by: string;
  started_at: string;
  completed_at?: string;
  actions_completed: number;
  logs_count: number;
}

interface ApprovalRequest {
  id: string;
  execution_id: string;
  action_id: string;
  action_name: string;
  action_type: string;
  parameters: Record<string, any>;
  requested_at: string;
}

interface SOARMetrics {
  total_playbooks: number;
  active_playbooks: number;
  total_executions: number;
  running_executions: number;
  successful_executions: number;
  failed_executions: number;
  success_rate: number;
  avg_execution_time_seconds: number;
  pending_approvals: number;
  system_health: number;
}

interface PlaybookTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  actions: Array<{
    type: string;
    name: string;
  }>;
}

const SOARPlatform: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'playbooks' | 'executions' | 'approvals' | 'templates'>('dashboard');
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [templates, setTemplates] = useState<PlaybookTemplate[]>([]);
  const [metrics, setMetrics] = useState<SOARMetrics | null>(null);
  const [selectedExecution, setSelectedExecution] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showCreatePlaybook, setShowCreatePlaybook] = useState(false);

  // Load initial data
  useEffect(() => {
    loadDashboardData();
    loadPlaybooks();
    loadExecutions();
    loadApprovals();
    loadTemplates();
    
    // Real-time updates
    const interval = setInterval(() => {
      loadDashboardData();
      loadExecutions();
      loadApprovals();
    }, 15000); // Update every 15 seconds

    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    try {
      const response = await fetch('/api/v1/soar/metrics');
      const data = await response.json();
      if (data.status === 'success') {
        setMetrics(data.metrics);
      }
    } catch (error) {
      console.error('Failed to load SOAR metrics:', error);
    }
  };

  const loadPlaybooks = async () => {
    try {
      const response = await fetch('/api/v1/soar/playbooks');
      const data = await response.json();
      if (data.status === 'success') {
        setPlaybooks(data.playbooks);
      }
    } catch (error) {
      console.error('Failed to load playbooks:', error);
    }
  };

  const loadExecutions = async () => {
    try {
      const response = await fetch('/api/v1/soar/executions');
      const data = await response.json();
      if (data.status === 'success') {
        setExecutions(data.executions);
      }
    } catch (error) {
      console.error('Failed to load executions:', error);
    }
  };

  const loadApprovals = async () => {
    try {
      const response = await fetch('/api/v1/soar/approvals');
      const data = await response.json();
      if (data.status === 'success') {
        setApprovals(data.approvals);
      }
    } catch (error) {
      console.error('Failed to load approvals:', error);
    }
  };

  const loadTemplates = async () => {
    try {
      const response = await fetch('/api/v1/soar/templates');
      const data = await response.json();
      if (data.status === 'success') {
        setTemplates(data.templates);
      }
    } catch (error) {
      console.error('Failed to load templates:', error);
    }
  };

  const updatePlaybookStatus = async (playbookId: string, status: string) => {
    try {
      setLoading(true);
      const response = await fetch(`/api/v1/soar/playbooks/${playbookId}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      
      if (response.ok) {
        loadPlaybooks();
      }
    } catch (error) {
      console.error('Failed to update playbook status:', error);
    } finally {
      setLoading(false);
    }
  };

  const triggerIncidentResponse = async (incidentData: Record<string, any>) => {
    try {
      setLoading(true);
      const response = await fetch('/api/v1/soar/incidents/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(incidentData)
      });
      
      const data = await response.json();
      if (data.status === 'triggered') {
        loadExecutions();
        loadDashboardData();
      }
    } catch (error) {
      console.error('Failed to trigger incident response:', error);
    } finally {
      setLoading(false);
    }
  };

  const processApproval = async (approvalId: string, approved: boolean, reason?: string) => {
    try {
      const response = await fetch(`/api/v1/soar/approvals/${approvalId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved, reason })
      });
      
      if (response.ok) {
        loadApprovals();
        loadExecutions();
      }
    } catch (error) {
      console.error('Failed to process approval:', error);
    }
  };

  const createPlaybookFromTemplate = async (templateId: string, customization: Record<string, any> = {}) => {
    try {
      setLoading(true);
      const response = await fetch(`/api/v1/soar/templates/${templateId}/create-playbook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(customization)
      });
      
      const data = await response.json();
      if (data.status === 'created') {
        loadPlaybooks();
        setActiveTab('playbooks');
      }
    } catch (error) {
      console.error('Failed to create playbook from template:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': case 'running': return <PlayIcon className="h-4 w-4 text-green-600" />;
      case 'paused': return <PauseIcon className="h-4 w-4 text-yellow-600" />;
      case 'completed': return <CheckCircleIcon className="h-4 w-4 text-blue-600" />;
      case 'failed': case 'cancelled': return <XCircleIcon className="h-4 w-4 text-red-600" />;
      case 'pending': case 'requires_approval': return <ClockIcon className="h-4 w-4 text-orange-600" />;
      default: return <StopIcon className="h-4 w-4 text-gray-600" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': case 'running': case 'completed': return 'text-green-600 bg-green-100';
      case 'paused': case 'pending': return 'text-yellow-600 bg-yellow-100';
      case 'failed': case 'cancelled': return 'text-red-600 bg-red-100';
      case 'requires_approval': return 'text-orange-600 bg-orange-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="soar-platform p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 flex items-center">
            <CogIcon className="h-8 w-8 mr-3 text-blue-600" />
            SOAR Platform
          </h1>
          <p className="text-gray-600 mt-1">Security Orchestration, Automation & Response</p>
        </div>
        
        <div className="flex space-x-3">
          <button
            onClick={() => triggerIncidentResponse({
              id: `test-${Date.now()}`,
              event_type: 'malware_detected',
              severity: 4,
              affected_host: '192.168.1.100'
            })}
            className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
            disabled={loading}
          >
            <BoltIcon className="h-4 w-4 mr-2 inline" />
            Simulate Incident
          </button>
          <button
            onClick={loadDashboardData}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
            disabled={loading}
          >
            <ArrowPathIcon className="h-4 w-4 mr-2 inline" />
            Refresh
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex space-x-1 mb-6 bg-gray-100 p-1 rounded-lg">
        {[
          { id: 'dashboard', label: 'Dashboard', icon: ChartBarIcon },
          { id: 'playbooks', label: 'Playbooks', icon: DocumentTextIcon },
          { id: 'executions', label: 'Executions', icon: PlayIcon },
          { id: 'approvals', label: 'Approvals', icon: ExclamationTriangleIcon },
          { id: 'templates', label: 'Templates', icon: PlusIcon }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center px-4 py-2 rounded-md transition-colors ${
              activeTab === tab.id
                ? 'bg-white text-blue-600 shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <tab.icon className="h-4 w-4 mr-2" />
            {tab.label}
            {tab.id === 'approvals' && approvals.length > 0 && (
              <span className="ml-2 bg-red-600 text-white text-xs rounded-full px-2 py-1">
                {approvals.length}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Dashboard Tab */}
      {activeTab === 'dashboard' && (
        <div className="space-y-6">
          {/* Metrics Cards */}
          {metrics && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Total Playbooks</p>
                    <p className="text-2xl font-bold text-gray-900">{metrics.total_playbooks}</p>
                    <p className="text-sm text-gray-500">{metrics.active_playbooks} active</p>
                  </div>
                  <DocumentTextIcon className="h-8 w-8 text-blue-600" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Total Executions</p>
                    <p className="text-2xl font-bold text-gray-900">{metrics.total_executions}</p>
                    <p className="text-sm text-gray-500">{metrics.running_executions} running</p>
                  </div>
                  <PlayIcon className="h-8 w-8 text-green-600" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Success Rate</p>
                    <p className="text-2xl font-bold text-gray-900">{(metrics.success_rate * 100).toFixed(1)}%</p>
                    <p className="text-sm text-gray-500">{metrics.successful_executions} successful</p>
                  </div>
                  <CheckCircleIcon className="h-8 w-8 text-green-600" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Avg Execution Time</p>
                    <p className="text-2xl font-bold text-gray-900">{Math.round(metrics.avg_execution_time_seconds)}s</p>
                    <p className="text-sm text-gray-500">Per playbook</p>
                  </div>
                  <ClockIcon className="h-8 w-8 text-purple-600" />
                </div>
              </div>
            </div>
          )}

          {/* Recent Executions */}
          <div className="bg-white rounded-lg shadow-sm border">
            <div className="p-6 border-b">
              <h3 className="text-lg font-semibold text-gray-900">Recent Executions</h3>
            </div>
            <div className="p-6">
              {executions.length === 0 ? (
                <p className="text-gray-500 text-center py-8">No executions yet</p>
              ) : (
                <div className="space-y-3">
                  {executions.slice(0, 5).map((execution) => (
                    <div key={execution.execution_id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-center space-x-3">
                        {getStatusIcon(execution.status)}
                        <div>
                          <p className="font-medium text-gray-900">Execution {execution.execution_id.slice(0, 8)}</p>
                          <p className="text-sm text-gray-600">
                            Playbook: {execution.playbook_id} | Actions: {execution.actions_completed}
                          </p>
                        </div>
                      </div>
                      <div className="text-right">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(execution.status)}`}>
                          {execution.status}
                        </span>
                        <p className="text-xs text-gray-500 mt-1">
                          {new Date(execution.started_at).toLocaleTimeString()}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Playbooks Tab */}
      {activeTab === 'playbooks' && (
        <div className="bg-white rounded-lg shadow-sm border">
          <div className="p-6 border-b flex justify-between items-center">
            <h3 className="text-lg font-semibold text-gray-900">Security Playbooks</h3>
            <button
              onClick={() => setShowCreatePlaybook(true)}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
            >
              <PlusIcon className="h-4 w-4 mr-2 inline" />
              Create Playbook
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Version</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created By</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Controls</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {playbooks.map((playbook) => (
                  <tr key={playbook.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900">{playbook.name}</div>
                        <div className="text-sm text-gray-500">{playbook.description}</div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getStatusIcon(playbook.status)}
                        <span className={`ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(playbook.status)}`}>
                          {playbook.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {playbook.version}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {playbook.actions_count} actions
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {playbook.created_by}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
                      {playbook.status === 'draft' && (
                        <button
                          onClick={() => updatePlaybookStatus(playbook.id, 'active')}
                          className="text-green-600 hover:text-green-900"
                          disabled={loading}
                        >
                          Activate
                        </button>
                      )}
                      {playbook.status === 'active' && (
                        <button
                          onClick={() => updatePlaybookStatus(playbook.id, 'paused')}
                          className="text-yellow-600 hover:text-yellow-900"
                          disabled={loading}
                        >
                          Pause
                        </button>
                      )}
                      <button className="text-blue-600 hover:text-blue-900">
                        <EyeIcon className="h-4 w-4 inline" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Executions Tab */}
      {activeTab === 'executions' && (
        <div className="bg-white rounded-lg shadow-sm border">
          <div className="p-6 border-b">
            <h3 className="text-lg font-semibold text-gray-900">Playbook Executions</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Execution ID</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Playbook</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Progress</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Started</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Triggered By</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {executions.map((execution) => (
                  <tr key={execution.execution_id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900">
                        {execution.execution_id.slice(0, 8)}...
                      </div>
                      <div className="text-sm text-gray-500">
                        Incident: {execution.incident_id}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {execution.playbook_id}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getStatusIcon(execution.status)}
                        <span className={`ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(execution.status)}`}>
                          {execution.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900">
                        {execution.actions_completed} actions completed
                      </div>
                      <div className="text-sm text-gray-500">
                        {execution.logs_count} log entries
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(execution.started_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {execution.triggered_by}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Approvals Tab */}
      {activeTab === 'approvals' && (
        <div className="bg-white rounded-lg shadow-sm border">
          <div className="p-6 border-b">
            <h3 className="text-lg font-semibold text-gray-900">Pending Approvals</h3>
          </div>
          <div className="p-6">
            {approvals.length === 0 ? (
              <p className="text-gray-500 text-center py-8">No pending approvals</p>
            ) : (
              <div className="space-y-4">
                {approvals.map((approval) => (
                  <div key={approval.id} className="border rounded-lg p-4">
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <h4 className="font-medium text-gray-900">{approval.action_name}</h4>
                        <p className="text-sm text-gray-600 mt-1">
                          Type: {approval.action_type} | Execution: {approval.execution_id.slice(0, 8)}
                        </p>
                        <div className="mt-2">
                          <p className="text-sm font-medium text-gray-700">Parameters:</p>
                          <pre className="text-xs text-gray-600 bg-gray-50 p-2 rounded mt-1">
                            {JSON.stringify(approval.parameters, null, 2)}
                          </pre>
                        </div>
                        <p className="text-xs text-gray-500 mt-2">
                          Requested: {new Date(approval.requested_at).toLocaleString()}
                        </p>
                      </div>
                      <div className="flex space-x-2 ml-4">
                        <button
                          onClick={() => processApproval(approval.id, true, 'Approved via UI')}
                          className="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700"
                        >
                          Approve
                        </button>
                        <button
                          onClick={() => processApproval(approval.id, false, 'Denied via UI')}
                          className="bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700"
                        >
                          Deny
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Templates Tab */}
      {activeTab === 'templates' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow-sm border">
            <div className="p-6 border-b">
              <h3 className="text-lg font-semibold text-gray-900">Playbook Templates</h3>
              <p className="text-gray-600 mt-1">Create playbooks from predefined templates</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 p-6">
              {templates.map((template) => (
                <div key={template.id} className="border rounded-lg p-4 hover:shadow-md transition-shadow">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h4 className="font-medium text-gray-900">{template.name}</h4>
                      <p className="text-sm text-gray-600 mt-1">{template.description}</p>
                      <div className="mt-3">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                          {template.category}
                        </span>
                      </div>
                      <div className="mt-3">
                        <p className="text-xs font-medium text-gray-700">Actions:</p>
                        <ul className="text-xs text-gray-600 mt-1 space-y-1">
                          {template.actions.slice(0, 3).map((action, index) => (
                            <li key={index}>• {action.name}</li>
                          ))}
                          {template.actions.length > 3 && (
                            <li>• +{template.actions.length - 3} more...</li>
                          )}
                        </ul>
                      </div>
                    </div>
                  </div>
                  <div className="mt-4">
                    <button
                      onClick={() => createPlaybookFromTemplate(template.id)}
                      disabled={loading}
                      className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
                    >
                      Create Playbook
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SOARPlatform;