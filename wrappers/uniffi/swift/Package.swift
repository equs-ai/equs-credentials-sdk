// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "asdk",
	platforms: [.iOS(.v15)],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		.library(
			name: "Asdk",
			targets: ["Asdk"]
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
			name: "Asdk",
			dependencies: ["AsdkFFI"],
			path: "Sources/Asdk",
			linkerSettings: [
				.linkedLibrary("z"),
				.linkedLibrary("iconv")
			]
		),

		.testTarget(
			name: "AsdkTests",
			dependencies: [
				"Asdk",
				.product(name: "Swifter", package: "swifter"),
			],
			path: "Tests/AsdkTests"
		),

		.binaryTarget(
			name: "AsdkFFI",
			path: "asdk.xcframework"
		),
	]
)
