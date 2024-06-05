# shadow-flow-go (temporary technical name)

### Test
```shell
go test
```

### Test with a poor coverage report
```shell
go test -cover
```

### Test with HTML coverage report
```shell
go test -coverprofile=coverage.out && go tool cover -html=coverage.out
```
