pipeline {
    agent any

    stages {
        stage('Clean') {
            steps {
                echo 'STEP1 ---------- Clean up the cloned projects'
                dir('SpringBootJwtDemo') {
                    echo 'Deleting SpringBootJwtDemo from build path...'
                    deleteDir()
                }
            }
        }
        stage('Clone') {
            steps {
                echo "STEP2 ---------- Clone project ..."
                bat 'git clone https://github.com/wanxiaolong/SpringBootJwtDemo'
            }
        }
        stage('Build') {
            steps {
                echo 'STEP3 ---------- Build project..'
                dir('SpringBootJwtDemo') {
                    bat "mvn clean install -Dmaven.test.skip=true"
                }
            }
        }
        stage('Unit Test') {
            steps {
                echo 'STEP4 ---------- Run unit test...'
                dir('SpringBootJwtDemo') {
                    bat "mvn test"
                }
            }
        }
        stage('Sonar Scan') {
            steps {
                echo "STEP5 ---------- Sonar Scan..."
                dir('SpringBootJwtDemo') {
                    bat "mvn sonar:sonar"
                }
            }
        }
        stage('Publish Artifact') {
            steps {
                echo "STEP6 ---------- Publish artifact..."
                echo "Executing scripts"
            }
        }
        stage('Deploy') {
            steps {
                echo 'STEP7 ---------- Deploy...'
            }
        }
    }
}