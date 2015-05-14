Checks to make sure docker is properly installed.

These tests require the `ubuntu:14.04` image. There's an example file in
`example/main.go` which gives an example of how to run the tests.

    $ go run example/main.go 
    CheckDockerSocketAccess ... OK (37.39603ms)
    CheckVersion            ... OK (704.645µs)
    CheckAUFSDriver         ... OK (38.370624ms)
    CheckSimpleCommand      ... OK (486.655433ms)
    CheckInternetAccess     ... OK (1.427594181s)
    CheckExposingPort       ... OK (1.0361052s)
    CheckFileMounting       ... OK (486.73578ms)
