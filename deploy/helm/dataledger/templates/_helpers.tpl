{{- define "dataledger.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "dataledger.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "dataledger.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "dataledger.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: dataledger
{{- end -}}

{{- define "dataledger.selector" -}}
app.kubernetes.io/name: {{ include "dataledger.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "dataledger.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}
{{- end -}}
{{- end -}}

{{- define "dataledger.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "dataledger.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "dataledger.secretName" -}}
{{- default (printf "%s-secrets" (include "dataledger.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{/* Settings shared by the API, the indexer and the migration step. */}}
{{- define "dataledger.commonEnv" -}}
- name: DATALEDGER_RPC_URL
  value: {{ required "chain.rpcUrl is required" .Values.chain.rpcUrl | quote }}
- name: DATALEDGER_DEPLOYMENT_FILE
  value: /etc/dataledger/deployment.json
- name: DATALEDGER_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "dataledger.secretName" . }}
      key: {{ .Values.secrets.keys.databaseUrl }}
- name: DATALEDGER_AUTO_MIGRATE
  value: "false"
- name: DATALEDGER_INDEXER_CONFIRMATIONS
  value: {{ .Values.chain.confirmations | quote }}
- name: DATALEDGER_LOG_FORMAT
  value: {{ .Values.logFormat | quote }}
- name: DATALEDGER_LOG_LEVEL
  value: {{ .Values.logLevel | quote }}
{{- end -}}

{{- define "dataledger.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
fsGroup: 10001
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "dataledger.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end -}}
