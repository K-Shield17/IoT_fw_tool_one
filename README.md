# IoT Firmware Security Assessment Tool

IoT 펌웨어를 정적 분석하여 주요 보안 위험 요소를 점검하고, HTML / JSON / CSV 형태의 결과를 생성하는 CLI 도구입니다.

## 1. 사용 목적

본 도구는 IoT 펌웨어를 빠르게 점검해야 하는 보안 담당자와 분석자를 대상으로 제작되었습니다.

복잡한 분석 환경 없이도 주요 보안 위험 요소를 정적 분석으로 확인하고, 결과를 보고서 형태로 정리하여 추가 점검 및 보안 조치에 활용할 수 있도록 하는 것을 목적으로 합니다.

## 2. 사용 방법
초기 구축 방법

```bash
git clone https://github.com/K-Shield17/IoT_fw_tool_one.git \

cd IoT_fw_tool_one \

chmod +x run.sh build.sh setup/*.sh tools/firmwalker-lite/firmwalker-lite.sh
```
실행 방법
```bash
./run.sh scan <firmware_file> -o <output_directory>
```

예시:

```bash
./run.sh scan ./IoTGoat.img -o results
```

별도의 수동 Build는 필수가 아니며, 필요한 경우 실행 과정에서 자동으로 Build됩니다.

## 3. 분석 결과

분석 성공 시 다음 파일이 생성됩니다.

```text
results/<target_name>/
├── report.html
├── report.json
└── report.csv
```

주요 결과는 `report.html`에서 확인할 수 있습니다.

```markdown
![Report Example](./docs/report_example.png)
```
