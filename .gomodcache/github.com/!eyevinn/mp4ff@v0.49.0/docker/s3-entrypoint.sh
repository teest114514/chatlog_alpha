#!/bin/sh

## Entry point script for Docker container to handle S3 URLs and execute commands

# Set default staging directory if not provided
if [ -z "$STAGING_DIR" ]; then
  STAGING_DIR="/usercontent"
fi

# Remove trailing slash from STAGING_DIR if it exists
STAGING_DIR="${STAGING_DIR%/}"

if [ $# -eq 0 ]; then
  echo "Error: No arguments provided"
  exit 1
fi

CMD="$1"
if [ ! -f "/usr/local/bin/$1" ]; then
  # No command found, execute the default command
  CMD="mp4ff-info"
else
  shift
fi

IS_INPUT="true"
for arg in "$@"; do
  case "$arg" in
    *s3://*|*s3-url*)
      # Check for credentials
      if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
        echo "Error: AWS credentials are not set. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables."
        exit 1
      fi
      ENDPOINT_URL=""
      if [ -n "$S3_ENDPOINT_URL" ]; then
        ENDPOINT_URL="--endpoint-url $S3_ENDPOINT_URL"
      fi
      # Extract S3 URL and download to local path
      S3_URL="$arg"
      LOCAL_FILE="$STAGING_DIR/$(basename "$S3_URL")"
      if [ "$IS_INPUT" = "true" ]; then
        echo "Downloading $S3_URL to $LOCAL_FILE"
        aws s3 $ENDPOINT_URL cp "$S3_URL" "$LOCAL_FILE"
        IS_INPUT="false"
      else
        if [ -z "$UPLOAD_FILES" ]; then
          UPLOAD_FILES="$S3_URL"
        else
          UPLOAD_FILES="$UPLOAD_FILES $S3_URL"
        fi
      fi
      # Replace S3 URL with local file path in arguments
      echo "$@" | sed "s|$S3_URL|$LOCAL_FILE|g"
      set -- $(echo "$@" | sed "s|$S3_URL|$LOCAL_FILE|g")
      ;;
  esac
done

$CMD "$@"

if [ -n "$UPLOAD_FILES" ]; then
  echo "Uploading files to S3: $UPLOAD_FILES"
  for s3url in $UPLOAD_FILES; do
    file="$STAGING_DIR/$(basename "$s3url")"    
    aws s3 $ENDPOINT_URL cp "$file" "$s3url"
  done
fi
