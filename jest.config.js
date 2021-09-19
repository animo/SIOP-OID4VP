module.exports = {
    preset: "ts-jest",
    testEnvironment: "node",
    moduleNameMapper: {
        "^jose/(.*)$": "<rootDir>/node_modules/jose/dist/node/cjs/$1",
    },
    rootDir: ".",
    roots: ["<rootDir>/src/", "<rootDir>/test/"],
    testMatch: ["**/?(*.)+(spec|test).+(ts|tsx|js)"],
    transform: {
        "^.+\\.(ts|tsx)?$": "ts-jest",
    },
    moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json"],
    coverageDirectory: "./coverage/",
    collectCoverageFrom: [
        "!src/schemas/**",
        "src/**/*.{ts,tsx}",
        "!src/**/*.d.ts",
        "!**/node_modules/**",
        "!jest.config.js",
        "!generator/**"
    ],
    collectCoverage: true,
    reporters: ["default", ["jest-junit", { outputDirectory: "./coverage" }]],
};
