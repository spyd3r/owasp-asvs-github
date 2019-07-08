# asvs

Create a github personal access token, then set an environment variable named GITHUB_PERSONAL_ACCESS_TOKEN with the value of your access token

The value of <verification_level> will dictate which issues will be associated to their corresponding ASVS milestones. For instance, a level 3 issue will not be assigned to a milestone if <verification_level> is set to 2. All issues regardless of their level will still be created.

```
./asvs.rb
Missing or invalid arguments: asvs.rb <project_name> <verification_level> <path_to_clone_repo>
Example: asvs.rb asvs-graphql 2 /home/bobdobs/projects/
```
