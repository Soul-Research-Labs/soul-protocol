{{/* Expand the name of the chart */}}
{{- define "relayer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "relayer.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "relayer.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "relayer.labels" -}}
app.kubernetes.io/name: {{ include "relayer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "relayer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "relayer.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
