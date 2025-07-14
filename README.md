# Implementation Guide for CrowdStrike Falcon Container Sensor in AWS EKS+Fargate

> **Note**: This is an open source project, not a CrowdStrike product. As such, it carries no formal support, expressed or implied.

This guide works through the deployment of Falcon Container Sensor to an EKS Fargate environment via Helm. **Estimated time to complete (assuming you have prerequisites) is 60-90 minutes.**


## Overview

### About Falcon Container Sensor

The Falcon Container sensor for Linux extends runtime security to container workloads in Kubernetes clusters that don’t allow you to deploy the kernel-based Falcon sensor for Linux. The Falcon Container sensor runs as an unprivileged container in user space with no code running in the kernel of the worker node OS. This allows it to secure Kubernetes pods in clusters where it isn’t possible to deploy the kernel-based Falcon sensor for Linux on the worker node, as with AWS Fargate where organizations don’t have access to the kernel and where privileged containers are disallowed. 

> **Note**: In Kubernetes clusters where kernel module loading is supported by the worker node OS, we recommend using Falcon sensor for Linux to secure both worker nodes and containers with a single sensor.**

## Pre-requisites

- Existing AWS Account
- You will need a workstation to complete the installation steps below
  * These steps have been tested on Linux and should also work with OSX
- Docker installed and running locally on the workstation
- API Credentials from Falcon (scope requirement defined on [pull script](https://github.com/CrowdStrike/falcon-scripts/tree/main/bash/containers/falcon-container-sensor-pull))
  * These credentials can be created in the Falcon platform under Support->API Clients and Keys.
  * For this step and practice of least privilege, you would want to create a dedicated API secret and key.


### Command line tools required:

1) Install [docker](https://www.docker.com/products/docker-desktop) container runtime
2) Install [kubectl](https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html)
3) Install [eksctl](https://docs.aws.amazon.com/eks/latest/userguide/eksctl.html)
4) Install [helm](https://helm.sh/docs/intro/install/)
5) Install [aws cli](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)

## Deployment Configuration Steps

### Step 1 (Retrieve Falcon Image and set up AWS variables): 5 minutes

The Falcon Container Sensor image is stored in the CrowdStrike private registry and the Falcon Cloud Security with Containers SKU is required to authenticate. Leverage the [pull script](https://github.com/CrowdStrike/falcon-scripts/tree/main/bash/containers/falcon-container-sensor-pull) to easily access the Falcon registry.

> **Note**: reference the [pull script](https://github.com/CrowdStrike/falcon-scripts/tree/main/bash/containers/falcon-container-sensor-pull) page for more usage information.

For AWS_REGION set our cluster AWS region (i.e us-east-1, us-west-2) and for APP_ARCH specify the sensor platform to retrieve based on your application, e.g., x86_64, aarch64

- Example:

    ```
    export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    export AWS_REGION=us-east-1
    export APP_ARCH=x86_64 or aarch64
    export FALCON_CLIENT_ID=xxxxxxx
    export FALCON_CLIENT_SECRET=xxxxxxx
    
    export FALCON_CID=$(bash <(curl -Ls https://github.com/CrowdStrike/falcon-scripts/releases/latest/download/falcon-container-sensor-pull.sh) -t falcon-container --get-cid)
    export LATESTSENSOR=$(bash <(curl -Ls https://github.com/CrowdStrike/falcon-scripts/releases/latest/download/falcon-container-sensor-pull.sh) -p $APP_ARCH -t falcon-container | tail -1)
    export FALCON_IMAGE_TAG=$(echo $LATESTSENSOR | cut -d':' -f 2)
    ```

- Now that we have the Falcon Container image on our local machine, we need to move it into ECR.

### Step 2 (Move to ECR): 10 minutes
Now that we have the image on our local machine, we need to tag it and push it into ECR so our EKS cluster can access it. To do that, we'll tag the image and use the push command to move it.

- Let's define our ECR repository and tag variables. This is the location in ECR you want to store your Falcon Container Sensor image. We'll use these later in the tutorial when we actually deploy as well. `Change to include your relevant AWS account, region, repo and tag`.

    ```
    export ECR_REPO=$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/<REPOSITORY_NAME>
    export EKS_CLUSTER_NAME=""
    ```

- Now that we have the image locally, we can tag it and push it into our ECR. First, list the images on your system using:
    ```
    docker image ls
    ```

- Find the image ```registry.crowdstrike.com/falcon-container/us-1/release/falcon-sensor``` **(cloud may vary)**. Next, tag that image for ECR:
    ```
    docker image tag registry.crowdstrike.com/falcon-container/us-1/release/falcon-sensor:7.27.0-6602.container.Release.US-1 $ECR_REPO:$FALCON_IMAGE_TAG
    ```
- Finally, we'll push that image into our ECR repository with:

    ```
    docker push $ECR_REPO:$FALCON_IMAGE_TAG
    ```

### Step 3 (Fargate Profile): 5 minutes

EKS cluster automatically decides which workloads shall be instantiated on Fargate vs EKS nodes. This decision process is configured by AWS entity called **Fargate Profile**. Fargate profiles assign workloads based on Kubernetes namespaces. By default `kube-system` and `default` namespaces are present on the cluster. Falcon Container Sensor will be deployed to `falcon-system` namespace.

- Now let's create the Fargate profile:
    ```
    eksctl create fargateprofile \
       --region $AWS_REGION \
       --cluster $EKS_CLUSTER_NAME \
       --name fp-falcon-system \
       --namespace falcon-system
    ```
         
   Example output:
   ```
   [ℹ]  creating Fargate profile "fp-falcon-system" on EKS cluster "eks-fargate-cluster"
   [ℹ]  created Fargate profile "fp-falcon-system" on EKS cluster "eks-fargate-cluster"
   ```

### Step 4 (OIDC Setup): 5-10 minutes

We need to create an OIDC provider so our injector can leverage a role to authenticate to ECR. Your cluster may already have a provider we can use, so we'll check for an existing option first.

 - Determine whether you have an existing IAM OIDC provider for your cluster. Retrieve your cluster's OIDC provider ID and store it in a variable.

   ```
   export OIDC_ID=$(aws eks describe-cluster --name $EKS_CLUSTER_NAME --region $AWS_REGION --query "cluster.identity.oidc.issuer" --output text | cut -d '/' -f 5)
   ```
 
 - Determine whether an IAM OIDC provider with your cluster's ID is already in your account.
 
   ```
   aws iam list-open-id-connect-providers | grep $OIDC_ID
   ```
    If output is returned from the previous command, then you already have a provider for your cluster and you can skip the next step. If no output is returned, then you must create an IAM OIDC provider for your cluster.
- Create an IAM OIDC identity provider for your cluster with the following command. Replace ```my-cluster``` with the name of your eks cluster value.

   ```
   eksctl utils associate-iam-oidc-provider --cluster $EKS_CLUSTER_NAME --region $AWS_REGION --approve
   ```

### Step 5 (IAM Role/Service Account): 10 minutes

 When running on AWS Fargate, IAM roles associated with the Fargate nodes are not propagated to the running pods. This section describes the steps needed to create and associate an IAM role with the kubernetes service account via the IAM OIDC Connector to allow the Falcon injector service to read container image information from ECR.

 - Setup your shell environment variables

   ```
   export IAM_POLICY_NAME="FalconContainerInjectorPolicy"
   export IAM_POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${IAM_POLICY_NAME}"
   export IAM_ROLE_NAME="${EKS_CLUSTER_NAME}-Falcon-Injector-Role"
   export IAM_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${IAM_ROLE_NAME}"
   ```

 - Create AWS IAM Policy json for ECR Image Pulling
   ```
   cat <<__END__ > policy.json
   {
      "Version": "2012-10-17",
      "Statement": [
            {
              "Sid": "AllowImagePull",
              "Effect": "Allow",
              "Action": [
                  "ecr:BatchGetImage",
                  "ecr:DescribeImages",
                  "ecr:GetDownloadUrlForLayer",
                  "ecr:ListImages"
              ],
              "Resource": "*"
            },
            {
              "Sid": "AllowECRSetup",
              "Effect": "Allow",
              "Action": [
                  "ecr:GetAuthorizationToken"
              ],
              "Resource": "*"
            }
        ]
   }
   __END__
   ````
- Now let's create that policy in AWS
    ```
   aws iam create-policy \
     --policy-name ${IAM_POLICY_NAME} \
     --policy-document 'file://policy.json' \
     --description "Policy to enable Falcon Container Injector to pull container image from ECR"
   ```

 - Use eksctl to create the OIDC IAM role for the service account using the newly created policy. Note the use of the `role-only` option as Helm will be creating the kubernetes serviceAccount in the following steps. (falcon-helm creates the kubernetes serviceAccount with the name of 'crowdstrike-falcon-sa').
   ```
   eksctl create iamserviceaccount \
      --name crowdstrike-falcon-sa \
      --namespace falcon-system \
      --region "$AWS_REGION" \
      --cluster "${EKS_CLUSTER_NAME}" \
      --attach-policy-arn "${IAM_POLICY_ARN}" \
      --role-name "${IAM_ROLE_NAME}" \
      --role-only \
      --approve
   ```

### Step 6 (Helm Installation): 10-15 minutes
We'll deploy the Falcon Container Sensor via Helm in this step. You can view more information on our Helm Charts [here](https://github.com/CrowdStrike/falcon-helm).

 - Install the Falcon Container Sensor using helm and setting the serviceAccount role annotation:
   ```
   helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm && helm repo update
   helm upgrade --install falcon-helm crowdstrike/falcon-sensor \
   -n falcon-system --create-namespace \
   --set falcon.cid=$FALCON_CID \
   --set falcon.tags="eks-fargate" \
   --set node.enabled=false \
   --set container.enabled=true \
   --set container.image.repository=$ECR_REPO \
   --set container.image.tag=$FALCON_IMAGE_TAG \
   --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=$IAM_ROLE_ARN
   ```
   Example output:
   ```
   Release "falcon-helm" does not exist. Installing it now.
   W0915 11:48:54.925693   27157 warnings.go:70] policy/v1beta1 PodSecurityPolicy is deprecated in v1.21+, unavailable in v1.25+
   W0915 11:49:01.984130   27157 warnings.go:70] policy/v1beta1 PodSecurityPolicy is deprecated in v1.21+, unavailable in v1.25+
   NAME: falcon-helm
   LAST DEPLOYED: Thu Sep 15 11:48:51 2022
   NAMESPACE: falcon-system
   STATUS: deployed
   REVISION: 1
   TEST SUITE: None
   NOTES:
   Thank you for installing the CrowdStrike Falcon Helm Chart!

   Access to the Falcon Linux and Container Sensor downloads at registry.crowdstrike.com are
   required to complete the install of this Helm chart. If an internal registry is used instead of registry.crowdstrike.com.
   the containerized sensor must be present in a container registry accessible from Kubernetes installation.
   CrowdStrike Falcon sensors will deploy across all pods as sidecars in your Kubernetes cluster after
   installing this Helm chart and starting a new pod deployment for all your applications.
   The default image name to deploy the pod sensor is `falcon-sensor`.

   When utilizing your own registry, an extremely common error on installation is accidentally forgetting to add your containerized
   sensor to your local image registry prior to executing `helm install`. Please read the Helm Chart's ReadMe
   for more deployment considerations.
   ```
 - (optional) Watch the progress of a deployment
   ```
   watch 'kubectl get pods -n falcon-system'
   ```
   Example output:
   ```
   NAME                                      READY   STATUS    RESTARTS   AGE
   falcon-sensor-injector-56f5ff68cc-ttgjj   1/1     Running   0          99s
   ```

 - To learn more about falcon-helm visit [upstream github](https://github.com/CrowdStrike/falcon-helm).


### Step 7 (Test App): 10 minutes
Now that we have our injector running successfully, we can test injection with a new deployment. CrowdStrike maintains a [vulnapp](https://github.com/CrowdStrike/vulnapp) project that can be used to generate test detections.

 - We can deploy the vulnerable app with a single command. 
   ```
   kubectl apply -f  https://raw.githubusercontent.com/crowdstrike/vulnapp/main/vulnerable.example.yaml
   ```
- If successful, we should see our pod running 2/2 with the Falcon Container Sensor being a sidecar to the application pod.

    ```
    kubectl get pods
    ```
    Example output:
    ```
    vulnerable.example.com-7fdcc89fb4-8zr49   2/2     Running           0          68s
    ```

- At this point, you should see a new entry in `Host management` within the CrowdStrike console. Sorting by `first seen = last hour` and `type = pod` is the easiest way.

>**Note**: To better understand how to use the vulnapp and generate detections, view the project directly [here](https://github.com/CrowdStrike/vulnapp).

### CONGRATS - You've successfully deployed the Falcon Container Sensor to EKS Fargate
![Image](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExaWM1ZnIzcHJqOWlsdDhmaTVsd3A5NHIzdjQ2enNva3Q2NDYxM2theSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/3o7abKhOpu0NwenH3O/giphy.gif)
=================================================================================    
## Uninstall Steps

- **Step 1**: Remove the vulnapp
   ```
   kubectl delete -f https://raw.githubusercontent.com/crowdstrike/vulnapp/main/vulnerable.example.yaml
   ```

 - **Step 2**: Uninstall helm release
   ```
   helm uninstall falcon-helm -n falcon-system
   ```
   Example output:
   ```
   release "falcon-helm" uninstalled
   ```
 - **Step 3**: Delete the falcon image from AWS ECR registry
   ```
   aws ecr batch-delete-image --region $CLOUD_REGION \
       --repository-name $ECR_REPO \
       --image-ids imageTag=$ECR_TAG
   ```
   Example output:
   ```
   {
       "imageIds": [
           {
               "imageDigest": "sha256:e14904d6fd47a8395304cd33a0d650c2b924f1241f0b3561ece8a515c87036df",
               "imageTag": "latest"
           }
       ],
       "failures": []
   }
   ```

- Step 4: Delete the created IAM Managed Policy
   ```
    aws iam delete-policy --policy-arn $IAM_POLICY_ARN
   ```

## CrowdStrike Contact Information
 - For questions regarding CrowdStrike offerings on AWS Marketplace or service integrations: [aws@crowdstrike.com](aws@crowdstrike.com)
 - For questions around product sales: [sales@crowdstrike.com](sales@crowdstrike.com)
 - For questions around support: [support@crowdstrike.com](support@crowdstrike.com)
 - For additional information and contact details: [https://www.crowdstrike.com/contact-us/](https://www.crowdstrike.com/contact-us/)
