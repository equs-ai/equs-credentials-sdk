import Foundation

/// Runs tasks on one thread with a large stack.
@available(iOS 18.0, macOS 15.0, *)
final class LargeStackExecutor: TaskExecutor, @unchecked Sendable {
	static let shared = LargeStackExecutor(stackSize: 8 << 20)

	private let condition = NSCondition()
	private var jobs: [UnownedJob] = []

	private init(stackSize: Int) {
		let thread = Thread { [self] in run() }
		thread.name = "LargeStackExecutor"
		thread.stackSize = stackSize
		thread.start()
	}

	func enqueue(_ job: consuming ExecutorJob) {
		let job = UnownedJob(job)
		condition.lock()
		jobs.append(job)
		condition.signal()
		condition.unlock()
	}

	private func run() {
		while true {
			condition.lock()
			while jobs.isEmpty {
				condition.wait()
			}
			let job = jobs.removeFirst()
			condition.unlock()
			job.runSynchronously(on: asUnownedTaskExecutor())
		}
	}
}
