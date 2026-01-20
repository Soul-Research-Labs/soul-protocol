export default function Loading() {
  return (
    <main className="min-h-screen bg-gradient-to-br from-pil-dark to-slate-900 flex items-center justify-center">
      <div className="text-center">
        {/* Animated Logo */}
        <div className="relative mb-8">
          <div className="w-20 h-20 rounded-2xl bg-gradient-pil flex items-center justify-center mx-auto animate-pulse">
            <span className="text-4xl font-bold text-white">π</span>
          </div>
          
          {/* Orbiting dots */}
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-32 h-32 relative animate-spin" style={{ animationDuration: '3s' }}>
              <div className="absolute top-0 left-1/2 -translate-x-1/2 w-3 h-3 rounded-full bg-pil-purple"></div>
              <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-3 h-3 rounded-full bg-pil-blue"></div>
              <div className="absolute left-0 top-1/2 -translate-y-1/2 w-3 h-3 rounded-full bg-pil-cyan"></div>
              <div className="absolute right-0 top-1/2 -translate-y-1/2 w-3 h-3 rounded-full bg-purple-400"></div>
            </div>
          </div>
        </div>

        <h2 className="text-xl font-semibold text-white mb-2">Loading PIL Protocol</h2>
        <p className="text-white/50">Initializing privacy infrastructure...</p>

        {/* Progress bar */}
        <div className="mt-8 w-64 mx-auto">
          <div className="h-1 bg-white/10 rounded-full overflow-hidden">
            <div className="h-full bg-gradient-pil rounded-full animate-pulse" style={{ width: '60%' }}></div>
          </div>
        </div>
      </div>
    </main>
  );
}
