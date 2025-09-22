import React, { useState, useEffect } from 'react';
import { ShieldCheckIcon, ServerIcon, ComputerDesktopIcon, CircleStackIcon } from '@heroicons/react/24/outline';

interface Asset {
  id: number;
  asset_id: string;
  name: string;
  asset_type: string;
  ip_address?: string;
  hostname?: string;
  risk_level: string;
  compliance_status: string;
  vulnerabilities_count: number;
  owner?: string;
  environment?: string;
  last_updated: string;
}

interface AssetSummary {
  total_assets: number;
  by_type: Record<string, number>;
  by_risk_level: Record<string, number>;
  by_compliance_status: Record<string, number>;
  recent_discoveries: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
}

const AssetManagement: React.FC = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [summary, setSummary] = useState<AssetSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedRisk, setSelectedRisk] = useState<string>('all');
  const [discoveryNetwork, setDiscoveryNetwork] = useState('192.168.1.0/24');
  const [isDiscovering, setIsDiscovering] = useState(false);

  // Mock data for demonstration
  const mockSummary: AssetSummary = {
    total_assets: 127,
    by_type: {
      server: 45,
      workstation: 67,
      database: 8,
      network_device: 5,
      application: 2
    },
    by_risk_level: {
      critical: 3,
      high: 12,
      medium: 45,
      low: 67
    },
    by_compliance_status: {
      compliant: 89,
      non_compliant: 15,
      partially_compliant: 18,
      not_assessed: 5
    },
    recent_discoveries: 8,
    total_vulnerabilities: 234,
    critical_vulnerabilities: 12
  };

  const mockAssets: Asset[] = [
    {
      id: 1,
      asset_id: 'ASSET-WEB01',
      name: 'Production Web Server',
      asset_type: 'server',
      ip_address: '192.168.1.10',
      hostname: 'web01.company.com',
      risk_level: 'high',
      compliance_status: 'compliant',
      vulnerabilities_count: 5,
      owner: 'IT Operations',
      environment: 'production',
      last_updated: '2025-09-18T10:30:00Z'
    },
    {
      id: 2,
      asset_id: 'ASSET-DB01',
      name: 'Customer Database',
      asset_type: 'database',
      ip_address: '192.168.1.20',
      hostname: 'db01.company.com',
      risk_level: 'critical',
      compliance_status: 'non_compliant',
      vulnerabilities_count: 12,
      owner: 'Data Team',
      environment: 'production',
      last_updated: '2025-09-18T09:15:00Z'
    },
    {
      id: 3,
      asset_id: 'ASSET-WS001',
      name: 'Admin Workstation',
      asset_type: 'workstation',
      ip_address: '192.168.1.100',
      hostname: 'admin-ws-001',
      risk_level: 'medium',
      compliance_status: 'compliant',
      vulnerabilities_count: 2,
      owner: 'John Smith',
      environment: 'production',
      last_updated: '2025-09-18T08:45:00Z'
    }
  ];

  useEffect(() => {
    // Simulate API call
    setTimeout(() => {
      setSummary(mockSummary);
      setAssets(mockAssets);
      setLoading(false);
    }, 1000);
  }, []);

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getComplianceColor = (status: string) => {
    switch (status) {
      case 'compliant': return 'text-green-600 bg-green-100';
      case 'non_compliant': return 'text-red-600 bg-red-100';
      case 'partially_compliant': return 'text-yellow-600 bg-yellow-100';
      case 'not_assessed': return 'text-gray-600 bg-gray-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getAssetIcon = (assetType: string) => {
    switch (assetType) {
      case 'server': return <ServerIcon className="h-5 w-5" />;
      case 'database': return <CircleStackIcon className="h-5 w-5" />;
      case 'workstation': return <ComputerDesktopIcon className="h-5 w-5" />;
      default: return <ShieldCheckIcon className="h-5 w-5" />;
    }
  };

  const handleDiscovery = async () => {
    setIsDiscovering(true);
    // Simulate network discovery
    setTimeout(() => {
      setIsDiscovering(false);
      alert(`Network discovery completed for ${discoveryNetwork}. Found 3 new assets.`);
    }, 3000);
  };

  const filteredAssets = assets.filter(asset => {
    if (selectedType !== 'all' && asset.asset_type !== selectedType) return false;
    if (selectedRisk !== 'all' && asset.risk_level !== selectedRisk) return false;
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-md p-4">
        <div className="flex">
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800">Error</h3>
            <div className="mt-2 text-sm text-red-700">{error}</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-gray-200 pb-4">
        <h1 className="text-2xl font-bold text-gray-900">Asset Management</h1>
        <p className="mt-2 text-sm text-gray-600">
          Comprehensive asset inventory, risk assessment, and compliance monitoring
        </p>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <ShieldCheckIcon className="h-6 w-6 text-blue-600" />
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Total Assets</dt>
                    <dd className="text-lg font-medium text-gray-900">{summary.total_assets}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="h-6 w-6 bg-red-600 rounded-full flex items-center justify-center">
                    <span className="text-xs font-bold text-white">{summary.critical_vulnerabilities}</span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Critical Vulnerabilities</dt>
                    <dd className="text-lg font-medium text-gray-900">{summary.total_vulnerabilities}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="h-6 w-6 bg-green-600 rounded-full flex items-center justify-center">
                    <span className="text-xs font-bold text-white">{summary.by_compliance_status.compliant}</span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Compliant Assets</dt>
                    <dd className="text-lg font-medium text-gray-900">{summary.by_compliance_status.compliant}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="h-6 w-6 bg-blue-600 rounded-full flex items-center justify-center">
                    <span className="text-xs font-bold text-white">{summary.recent_discoveries}</span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Recent Discoveries</dt>
                    <dd className="text-lg font-medium text-gray-900">{summary.recent_discoveries}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Network Discovery */}
      <div className="bg-white shadow rounded-lg p-6">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Network Discovery</h3>
        <div className="flex items-center space-x-4">
          <input
            type="text"
            value={discoveryNetwork}
            onChange={(e) => setDiscoveryNetwork(e.target.value)}
            placeholder="Network range (e.g., 192.168.1.0/24)"
            className="flex-1 rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          />
          <button
            onClick={handleDiscovery}
            disabled={isDiscovering}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {isDiscovering ? 'Discovering...' : 'Start Discovery'}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white shadow rounded-lg p-6">
        <div className="flex flex-wrap gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Asset Type</label>
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            >
              <option value="all">All Types</option>
              <option value="server">Servers</option>
              <option value="workstation">Workstations</option>
              <option value="database">Databases</option>
              <option value="network_device">Network Devices</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Risk Level</label>
            <select
              value={selectedRisk}
              onChange={(e) => setSelectedRisk(e.target.value)}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            >
              <option value="all">All Risk Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Asset List */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">
            Assets ({filteredAssets.length})
          </h3>
          <div className="space-y-4">
            {filteredAssets.map((asset) => (
              <div key={asset.id} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="flex-shrink-0">
                      {getAssetIcon(asset.asset_type)}
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">{asset.name}</h4>
                      <p className="text-sm text-gray-500">{asset.asset_id}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <div className="text-right">
                      <p className="text-sm text-gray-900">{asset.ip_address}</p>
                      <p className="text-sm text-gray-500">{asset.hostname}</p>
                    </div>
                    <div className="flex space-x-2">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRiskColor(asset.risk_level)}`}>
                        {asset.risk_level}
                      </span>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getComplianceColor(asset.compliance_status)}`}>
                        {asset.compliance_status.replace('_', ' ')}
                      </span>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-medium text-gray-900">{asset.vulnerabilities_count} vulns</p>
                      <p className="text-sm text-gray-500">{asset.owner}</p>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AssetManagement;