export async function runPool(items, worker, options = {}) {
  const concurrency = Math.max(1, Math.min(32, Number(options.concurrency) || 8));
  const signal = options.signal;
  const onProgress = options.onProgress || (() => {});
  const total = items.length;
  let next = 0;
  let active = 0;
  let completed = 0;
  const startedAt = performance.now();

  return new Promise(resolve => {
    const pump = () => {
      if ((signal?.aborted || next >= total) && active === 0) {
        resolve({ completed, total, aborted: Boolean(signal?.aborted), elapsedMs: performance.now() - startedAt });
        return;
      }
      while (!signal?.aborted && active < concurrency && next < total) {
        const index = next++;
        active++;
        Promise.resolve(worker(items[index], index))
          .catch(error => ({ status: 'failed', reason: error?.message || 'Worker failed', latency: null, testedAt: Date.now() }))
          .then(result => {
            active--;
            completed++;
            const elapsedSec = Math.max(.1, (performance.now() - startedAt) / 1000);
            const rate = completed / elapsedSec;
            const etaSec = Math.ceil((total - completed) / Math.max(.1, rate));
            onProgress({ item: items[index], index, result, completed, total, active, rate, etaSec });
            pump();
          });
      }
      if (signal?.aborted && active === 0) resolve({ completed, total, aborted: true, elapsedMs: performance.now() - startedAt });
    };
    pump();
  });
}
