# Password Hashing Benchmarks

This project benchmarks and analyzes the performance, resource usage, and security properties of three widely-used password hashing algorithms—**Argon2id**, **bcrypt**, and **PBKDF2-HMAC-SHA256**—to guide secure password storage decisions in modern systems. Developed as part of my [Cryptography Portfolio](https://github.com/Rob-Gravelle/cryptography_portfolio), this project demonstrates my ability to design, evaluate, and refine cryptographic benchmarks through an iterative process.

The project is presented in three versions (V1, V2, V3), each reflecting progressive improvements to showcase the iterative refinement process critical to cryptographic research and development.

## Project Overview
- **Purpose**: To compare the performance (hashing time), memory usage, output length, and security features of Argon2id, bcrypt, and PBKDF2, providing actionable recommendations for secure password storage.
- **Methodology**: Benchmarks were conducted using Python (libraries: `argon2-cffi`, `bcrypt`, `hashlib`, `psutil`) on a modern system (Windows 11, Intel i5-12400, 16GB RAM) with the test password "correcthorsebatterystaple".
- **Educational Value**: The project emphasizes clarity, correctness, and practical insights, serving as both a learning tool and a professional showcase of applied cryptography.

## Version Progression
The project is structured in three versions, each building on the previous to address limitations and incorporate advanced features:

### V1: Initial Benchmark
- **Description**: Establishes baseline performance and security analysis of Argon2id, bcrypt, and PBKDF2 with initial test parameters (e.g., Argon2id memory_cost up to 256MB, bcrypt rounds up to 14, PBKDF2 iterations up to 1M).
- **Key Features**:
  - Measures average hashing time, memory usage (via psutil), and output length.
  - Provides initial recommendations (e.g., Argon2id for modern systems).
  - Notes limitations, such as Windows-only testing and psutil’s memory tracking constraints.
- **Files**:
  - [Password_Hashing_Benchmarks.pdf](V1/Password%20Hashing%20Benchmarks.pdf)
  - [Code](V1/benchmark_utils.py) (Python script for benchmarking)
- **Limitations**: Limited test parameter ranges, single-platform testing, and lack of attack simulations.

### V2: Enhanced Benchmark
- **Description**: Improves upon V1 by expanding test parameters, adding cross-platform testing, and introducing basic attack simulations for enhanced robustness.
- **Improvements** (Planned):
  - Broader test ranges (e.g., Argon2id memory_cost up to 512MB, bcrypt rounds up to 15, PBKDF2 iterations up to 2M).
  - Cross-platform testing on Linux (e.g., Ubuntu via WSL) and/or macOS to compare performance across operating systems.
  - Basic attack simulation estimating brute-force times using a hypothetical GPU (e.g., RTX 4090).
- **Files** (To be added):
  - [Password_Hashing_Benchmarks_v2.pdf](v2/Password_Hashing_Benchmarks_v2.pdf)
  - [Code](v2/benchmark_utils.py) (Updated Python script)
- **Focus**: Addresses V1’s limitations by improving scalability and real-world applicability.

### V3: Future-Ready Benchmark
- **Description**: The final version incorporates forward-thinking elements, such as visualizations, energy consumption metrics, and alignment with modern cryptographic standards, making it a comprehensive resource for secure system design.
- **Additions** (Planned):
  - Visualizations (e.g., matplotlib charts comparing hashing time and memory usage).
  - Energy consumption analysis using tools like Intel Power Gadget or `powerstat`.
  - Discussion of Argon2id’s adoption in frameworks (e.g., Django, OWASP) and PBKDF2’s role in NIST SP 800-132.
- **Files** (To be added):
  - [Password_Hashing_Benchmarks_v3.pdf](v3/Password_Hashing_Benchmarks_v3.pdf)
  - [Code](v3/benchmark_utils.py) (Final Python script)
  - [Visuals](v3/visuals/) (Charts in PNG format)
- **Focus**: Enhances usability and relevance for modern and future cryptographic applications.

## Key Findings
- **Argon2id**: The best choice for modern systems due to its memory-hardness, GPU/ASIC resistance, and scalability with tunable parameters (e.g., 0.0503s at 8 threads).
- **bcrypt**: Suitable for legacy systems but scales exponentially with rounds (e.g., 1.2555s at 14 rounds), lacking memory-hardness.
- **PBKDF2**: NIST-compliant but vulnerable to GPU attacks due to lack of memory-hardness; requires manual salt management.
- **Recommendation**: Use memory-hard algorithms like Argon2id with at least 100ms hashing time, and benchmark regularly as hardware evolves.

## How to Run the Benchmarks
1. Clone the repository: `git clone https://github.com/Rob-Gravelle/cryptography_portfolio.git`
2. Navigate to the desired version’s code directory (e.g., `cd password_hashing_benchmarks/v1`)
3. Install dependencies: `pip install -r requirements.txt`
4. Run the benchmark script: `python benchmark_utils.py`
   - See the script’s comments for configuration details (e.g., adjusting memory_cost, rounds, iterations).

## Why Three Versions?
The iterative approach (V1 → V2 → V3) reflects the real-world process of cryptographic benchmarking, where algorithms and implementations evolve based on new insights, hardware advancements, and emerging threats. This structure showcases my ability to:
- Design and execute rigorous benchmarks (V1).
- Critically evaluate and address limitations (V2).
- Anticipate future trends and standards (V3).

## Future Work
This project will continue to evolve with:
- Additional platforms (e.g., ARM-based systems).
- Advanced attack simulations (e.g., dictionary attacks with real-world datasets).
- Integration with real-world applications (e.g., password hashing in a web framework).

## License
This repository is licensed under the MIT License. Feel free to use and modify the code with proper attribution.

---

[Back to Cryptography Portfolio](https://github.com/Rob-Gravelle/cryptography_portfolio)