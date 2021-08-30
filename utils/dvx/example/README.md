# Example

Steps to run this example with GoLand:

1. Edit Configuration
2. Add new Configuration > Go Build
3. Run on > Create New Targets > Docker ...
4. Docker server: Create or choose existing
5. Image: Build
6. Dockerfile: `utils/dvx/example/Dockerfile`
7. Context folder: `utils`
8. Open Optional
9. Image tag: softhsm
10. Set "Run options" to: "`--rm -v /home/fharw/repos/zoo-private/utils:/app:ro -v /home/fharw/repos/zoo-private/utils/dvx/example/softhsm-conf:/tmp/softhsm-conf:Z -it`"
11. Check mark at "Run image automatically every time before running code"
12. Click Next and let GoLand build the image
13. Verify that build was successful and introspection shows correct results > Next
14. Leave "Project path on target" as "`/app`" and don't change the introspected Go Configuration > Finish
15. Run kind: Package
16. Package path: `dvx/example`
17. Check mark at "Build on remote target" and leave "Run after build" also checked
18. Change working directory to: `/home/fharw/repos/zoo-private/utils`
19. Apply
20. `mkdir utils/dvx/example/softhsm-conf/tokendir`
21. `docker run --rm -v /home/fharw/repos/zoo-private/utils/dvx/example/softhsm-conf:/tmp/softhsm-conf:Z -it -e SOFTHSM2_CONF=/tmp/softhsm-conf/conf softhsm`
22. Inside container run: `softhsm2-util --init-token --slot 0 --label "dvx"`
23. Enter 1234 as User Pin
24. Enter 12345678 as Security Officer Pin
25. Exit container with "`exit`"
26. Run target with GoLand
27. Or run target by entering: `docker run --rm -v /home/fharw/repos/zoo-private/utils:/app:ro -v /home/fharw/repos/zoo-private/utils/dvx/example/softhsm-conf:/tmp/softhsm-conf:Z -it -e SOFTHSM2_CONF=/tmp/softhsm-conf/conf softhsm go run main.go`
