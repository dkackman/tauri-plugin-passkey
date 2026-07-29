// swift-tools-version:5.9

import PackageDescription

let package = Package(
    name: "tauri-plugin-webauthn",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "tauri-plugin-webauthn",
            type: .static,
            targets: ["tauri-plugin-webauthn"]
        )
    ],
    dependencies: [
        .package(name: "Tauri", path: "../.tauri/tauri-api")
    ],
    targets: [
        .target(
            name: "tauri-plugin-webauthn",
            dependencies: [
                .byName(name: "Tauri")
            ],
            path: "Sources"
        )
    ]
)
