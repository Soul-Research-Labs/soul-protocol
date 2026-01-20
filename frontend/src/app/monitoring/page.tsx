import { MonitoringDashboard } from '@/components/MonitoringDashboard';
import Header from '@/components/Header';

export const metadata = {
  title: 'System Monitoring | PIL Protocol',
  description: 'Real-time monitoring and analytics for PIL Protocol infrastructure',
};

export default function MonitoringPage() {
  return (
    <>
      <Header />
      <main className="min-h-screen bg-gradient-to-br from-pil-dark to-slate-900 pt-24 pb-16">
        <div className="container mx-auto px-6">
          {/* Page Header */}
          <div className="mb-8">
            <div className="flex items-center gap-3 mb-2">
              <span className="text-3xl">📡</span>
              <h1 className="text-3xl font-bold text-white">System Monitoring</h1>
            </div>
            <p className="text-white/60">
              Real-time infrastructure health, metrics, and protocol analytics
            </p>
          </div>

          {/* Monitoring Dashboard */}
          <MonitoringDashboard />
        </div>
      </main>
    </>
  );
}
