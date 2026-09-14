# IoT Firmware Security Assessment Tool

IoT 펌웨어를 정적 분석하여 주요 보안 위험 요소를 점검하고, HTML / JSON / CSV 형태의 결과를 생성하는 CLI 도구입니다.

## 1. 사용 목적

본 도구는 IoT 펌웨어를 빠르게 점검해야 하는 보안 담당자와 분석자를 대상으로 제작되었습니다.

복잡한 분석 환경 없이도 주요 보안 위험 요소를 정적 분석으로 확인하고, 결과를 보고서 형태로 정리하여 추가 점검 및 보안 조치에 활용할 수 있도록 하는 것을 목적으로 합니다.

## 2. 사용 방법
git clone 전 해야할 명령어 
```bash
sudo apt upgrade
sudo apt update
```
초기 구축 방법

```bash
git clone https://github.com/K-Shield17/IoT_fw_tool_one.git \

cd IoT_fw_tool_one \

chmod +x run.sh build.sh setup/*.sh tools/firmwalker-lite/firmwalker-lite.sh \

./build.sh
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

## 4. 오픈소스 라이선스 고지

본 도구는 다음 오픈소스 프로젝트의 소스코드를 일부 발췌·수정하여 포함하고 있습니다. 각 구성요소의 저작권은 원저작자에게 있으며, 아래 명시된 라이선스 조건에 따라 사용·배포됩니다.

각 라이선스의 전체 조건은 해당 구성요소 디렉터리의 `LICENSE` 파일에 원문 그대로 포함되어 있으며, 이용 시 반드시 해당 파일을 확인하시기 바랍니다.

| 구성요소 | 원본 프로젝트 | 저작권자 | 라이선스 | 라이선스 전문 |
|---|---|---|---|---|
| `tools/binwalk-lite/` | [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) | Copyright (c) 2024 devttys0 | MIT | [LICENSE](./tools/binwalk-lite/LICENSE) |
| `tools/firmwalker-lite/` | [craigz28/firmwalker](https://github.com/craigz28/firmwalker) | Copyright (c) Craig Smith | GPL-3.0 | [LICENSE](./tools/firmwalker-lite/LICENSE) |
| `tools/checksec-lite/` | [slimm609/checksec](https://github.com/slimm609/checksec) | Copyright (c) 2014-2022 Brian Davis<br>Copyright (c) 2013 Robin David<br>Copyright (c) 2009-2011 Tobias Klein | BSD 3-Clause | [LICENSE](./tools/checksec-lite/LICENSE) |

포함된 각 원본 파일의 목록과 무결성 해시값은 [`UPSTREAM_SELECTED_SHA256.txt`](./UPSTREAM_SELECTED_SHA256.txt)에서 확인할 수 있습니다.

### 4.1 원본 대비 수정 사항

각 구성요소는 원본을 그대로 포함한 것이 아니라, IoT 펌웨어 정적분석에 필요한 기능만 선별하여 수정한 파생 저작물입니다.

| 구성요소 | 주요 변경 사항 |
|---|---|
| `binwalk-lite` | IoT 펌웨어에서 출현하는 파일시스템·압축 형식의 시그니처 및 추출기만 선별 포함, 그 외 형식과 분석에 불필요한 기능 제외 |
| `firmwalker-lite` | 외부 서비스(Shodan) 연동, 이메일 수집, 정적 코드 분석 등 본 도구의 범위에 해당하지 않는 기능 제거, 탐색 범위를 주요 경로 중심으로 조정, 구조화된 출력 형식 및 심각도 등급 부여 로직 추가 |
| `checksec-lite` | 정적 판정이 가능한 검사 항목만 선별 포함, 커널 설정 및 실행 중 프로세스 점검 등 런타임 의존 기능 제외, 출력 형식을 JSON으로 변경 |

### 4.2 본 프로젝트의 라이선스

본 프로젝트는 서로 다른 라이선스의 구성요소를 포함하고 있습니다. 각 구성요소의 라이선스는 위에 명시된 대로 유지되나, 이들을 결합한 **저작물 전체는 GPL-3.0**을 따릅니다.

이는 GPL-3.0이 파생 저작물 전체에 동일 라이선스 적용을 요구하기 때문이며, MIT와 BSD 3-Clause는 GPL-3.0과 호환되므로 결합에 법적 문제가 없습니다.

| 이용 범위 | 적용 라이선스 |
|---|---|
| `tools/binwalk-lite/` 단독 이용 | MIT |
| `tools/checksec-lite/` 단독 이용 | BSD 3-Clause |
| `tools/firmwalker-lite/` 단독 이용 | GPL-3.0 |
| **본 도구 전체 이용** | **GPL-3.0** |

전체 라이선스 조건은 [`LICENSE`](./LICENSE) 파일을 참조하십시오.

### 4.3 실행 시 사용되는 외부 도구

본 도구는 분석 과정에서 아래 외부 유틸리티를 호출합니다. 해당 도구들은 본 저장소에 포함되어 있지 않으며, 실행 환경에 별도로 설치됩니다. 각 도구의 라이선스는 해당 배포처의 조건을 따릅니다.

`unsquashfs`(squashfs-tools) · `jefferson` · `ubi_reader` · `sasquatch` · `unyaffs` · `7z`(p7zip) · `zstd` · `tar` · `jq`
