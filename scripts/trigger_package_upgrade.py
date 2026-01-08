import json
import os
import sys
from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication

#!/usr/bin/env python3
"""
Trigger package upgrade pipeline for containerd dependencies.
Reads package versions from containerd_release_analysis.json and triggers
Azure DevOps pipeline for each package.
"""



def load_release_analysis(json_file='containerd_release_analysis.json'):
    """Load the containerd release analysis JSON file."""
    try:
        with open(json_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: {json_file} not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing JSON: {e}")
        sys.exit(1)


def trigger_pipeline(organization_url, project, pipeline_id, pat, parameters):
    """
    Trigger Azure DevOps pipeline with given parameters.
    
    Args:
        organization_url: Azure DevOps organization URL
        project: Project name
        pipeline_id: Pipeline definition ID
        pat: Personal Access Token
        parameters: Dictionary of pipeline parameters
    """
    # Create a connection to Azure DevOps
    credentials = BasicAuthentication('', pat)
    connection = Connection(base_url=organization_url, creds=credentials)
    
    # Get build client
    build_client = connection.clients.get_build_client()
    
    # Trigger the pipeline
    build = build_client.queue_build(
        build={
            'definition': {'id': pipeline_id},
            'parameters': json.dumps(parameters)
        },
        project=project
    )
    
    return build


def main():
    # Configuration
    ORGANIZATION_URL = "https://dev.azure.com/mariner-org"
    PROJECT = "mariner"
    PIPELINE_ID = 1770
    MARINER_BRANCH = "3.0-dev"
    UPGRADE_REASON = "validation new containerd release"
    
    # Get PAT from environment variable
    PAT = os.getenv('AZURE_DEVOPS_PAT')
    if not PAT:
        print("❌ Error: AZURE_DEVOPS_PAT environment variable not set")
        print("   Please set it with: export AZURE_DEVOPS_PAT='your-token'")
        sys.exit(1)
    
    # Load release analysis
    print("📖 Loading containerd release analysis...")
    data = load_release_analysis()
    
    containerd_version = data.get('containerd_version', 'unknown')
    dependencies = data.get('dependencies', {})
    
    print(f"📦 Containerd version: {containerd_version}")
    print(f"📊 Found {len(dependencies)} dependencies\n")
    
    if not dependencies:
        print("⚠️  No dependencies found in analysis file")
        sys.exit(0)
    
    # Trigger pipeline for each dependency
    triggered_builds = []
    failed_builds = []
    
    for component_name, version_info in dependencies.items():
        new_version = version_info.get('version', '')
        
        if not new_version:
            print(f"⚠️  Skipping {component_name}: no version found")
            continue
        
        print(f"🚀 Triggering pipeline for {component_name} → {new_version}")
        
        parameters = {
            'marinerBranch': MARINER_BRANCH,
            'componentName': component_name,
            'newVersion': new_version,
            'upgradeReason': UPGRADE_REASON
        }
        
        try:
            build = trigger_pipeline(
                ORGANIZATION_URL,
                PROJECT,
                PIPELINE_ID,
                PAT,
                parameters
            )
            
            build_url = f"{ORGANIZATION_URL}/{PROJECT}/_build/results?buildId={build.id}"
            print(f"   ✅ Build #{build.id} triggered: {build_url}")
            triggered_builds.append((component_name, build.id, build_url))
            
        except Exception as e:
            print(f"   ❌ Failed to trigger build: {e}")
            failed_builds.append((component_name, str(e)))
    
    # Summary
    print("\n" + "="*80)
    print("📊 Summary:")
    print(f"   ✅ Successfully triggered: {len(triggered_builds)}")
    print(f"   ❌ Failed: {len(failed_builds)}")
    
    if triggered_builds:
        print("\n🎉 Triggered builds:")
        for component, build_id, url in triggered_builds:
            print(f"   • {component}: Build #{build_id}")
            print(f"     {url}")
    
    if failed_builds:
        print("\n❌ Failed builds:")
        for component, error in failed_builds:
            print(f"   • {component}: {error}")
        sys.exit(1)


if __name__ == '__main__':
    main()