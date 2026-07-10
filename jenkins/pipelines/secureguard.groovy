pipeline {
    agent any

    environment {
        GITEA_TOKEN = credentials('gitea-token')
        REPO_URL    = "${params.REPO_URL}"
        COMMIT_SHA  = "${params.COMMIT_SHA}"
        REPO_NAME   = "${params.REPO_NAME}"
    }

    parameters {
        string(name: 'REPO_URL',   defaultValue: '', description: 'Gitea repo clone URL')
        string(name: 'COMMIT_SHA', defaultValue: '', description: 'Commit to scan')
        string(name: 'REPO_NAME',  defaultValue: '', description: 'owner/repo')
    }

    stages {
        stage('Checkout') {
            steps {
                sh 'rm -rf scan_workspace && mkdir scan_workspace'
                sh 'git clone --depth=1 ${REPO_URL} scan_workspace'
                sh 'cd scan_workspace && git checkout ${COMMIT_SHA}'
            }
        }

        stage('Parallel Security Scan') {
            parallel {
                stage('Semgrep SAST') {
                    steps {
                        sh '''
                            docker run --rm -v $(pwd)/scan_workspace:/src \
                                returntocorp/semgrep:latest \
                                semgrep --config=auto --json --quiet /src \
                                > reports/semgrep.json || true
                        '''
                    }
                }
                stage('Bandit') {
                    steps {
                        sh '''
                            docker run --rm -v $(pwd)/scan_workspace:/src \
                                python:3.11-slim bash -c \
                                "pip install bandit -q && bandit -r /src -f json -q" \
                                > reports/bandit.json || true
                        '''
                    }
                }
                stage('Gitleaks') {
                    steps {
                        sh '''
                            docker run --rm -v $(pwd)/scan_workspace:/path \
                                zricethezav/gitleaks:latest detect \
                                --source /path --report-format json \
                                --report-path /path/gitleaks.json --no-git || true
                            cp scan_workspace/gitleaks.json reports/ || true
                        '''
                    }
                }
                stage('Trivy') {
                    steps {
                        sh '''
                            docker run --rm -v $(pwd)/scan_workspace:/src \
                                aquasec/trivy:latest fs --format json --quiet /src \
                                > reports/trivy.json || true
                        '''
                    }
                }
            }
        }

        stage('Notify Orchestrator') {
            steps {
                sh '''
                    curl -X POST http://orchestrator:8000/webhook/gitea \
                        -H "Content-Type: application/json" \
                        -d "{\\"repository\\":{\\"clone_url\\":\\"${REPO_URL}\\",\\"full_name\\":\\"${REPO_NAME}\\"},\\"after\\":\\"${COMMIT_SHA}\\"}"
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/*.json', allowEmptyArchive: true
        }
    }
}
