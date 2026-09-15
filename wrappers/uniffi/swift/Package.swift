// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "equs-credentials-sdk",
	platforms: [.iOS(.v15)],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		.library(
			name: "EqusSdk",
			targets: ["EqusSdk"]
		)
	],
	dependencies: [
		.package(
			url: "https://github.com/httpswift/swifter.git",
			.upToNextMajor(from: "1.5.0")
		)
	],
	targets: [
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.target(
			name: "EqusSdk",
			dependencies: ["EqusSdkFFI"],
			path: "Sources/EqusSdk",
			linkerSettings: [
				.linkedLibrary("z"),
				.linkedLibrary("iconv")
			]
		),

		.testTarget(
			name: "EqusSdkTests",
			dependencies: [
				"EqusSdk",
				.product(name: "Swifter", package: "swifter"),
			],
			path: "Tests/EqusSdkTests"
		),

		.binaryTarget(
			name: "EqusSdkFFI",
			path: "equssdk.xcframework"
		),
	]
)
