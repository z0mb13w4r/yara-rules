#!/bin/bash

VERSION=0.0
SCRIPTNAME=$(basename "$0")

CATBIN=/usr/bin/cat
YARABIN=/usr/bin/yara

function show_usage() {
  ${CATBIN} << EOF
Usage: ${SCRIPTNAME} v${VERSION}
EXAMPLES:
  ${SCRIPTNAME} <source/path/name>
  ${SCRIPTNAME} <source/path/name> {-c|--check} <source/path/yara/rule>
  ${SCRIPTNAME} {-u|--update}
  ${SCRIPTNAME} {-v|--version}
  ${SCRIPTNAME} {-h|--help}
EOF
}

function show_version() {
  echo "${SCRIPTNAME} v${VERSION}"
}

function yara_run() {
  if [ -e "${1}" ]; then
    ${YARABIN} -w "${1}" "${2}"
  fi
}

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case ${1} in
    -c|--check)
      ARG_YARA_CHECK="${2}"
      shift # past argument
      shift # past value
      ;;
    -u|--update)
      ARG_YARA_UPDATE=YES
      shift # past argument
      ;;
    -h|--help)
      ARG_HELP=YES
      shift # past argument
      ;;
    -v|--version)
      ARG_VERSION=YES
      shift # past argument
      ;;
    -*|--*)
      echo "Unknown option ${1}"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("${1}") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [ "${ARG_HELP}" == "YES" ]; then
  show_usage
  exit 0
elif [ "${ARG_VERSION}" == "YES" ]; then
  show_version
  exit 0
fi

if [ "${ARG_YARA_UPDATE}" == "YES" ]; then
  echo TBD
elif [ ! -z "${POSITIONAL_ARGS}" ]; then
  if [ ! -z "${ARG_YARA_CHECK}" ]; then
    yara_run "${ARG_YARA_CHECK}" "${POSITIONAL_ARGS}"
  else
    yara_run "index.yar" "${*}"
  fi
else
  show_usage
  exit 1
fi

exit 0
