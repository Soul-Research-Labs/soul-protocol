import { MonitoringDashboard } from '@/components/MonitoringDashboard';

export default function MonitoringPage() {
  return (
    <main className="min-h-screen bg-gray-900 py-8">
      <div className="container mx-auto px-4">
        <MonitoringDashboard />
      </div>
    </main>
  );
}
