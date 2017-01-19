# eiseno

The admin for [Onesie](https://www.onesie.website). You can view the serving code at [icco/onesie](http://github.com/icco/onesie).

## Documentation

 - To generate a new migration:

```
go get -u github.com/mattes/migrate
migrate -url postgres://localhost/eiseno?sslmode=disable -path ./db/migrations create migration_file_xyz
```

 - To Install Deps

```
go get -u github.com/tools/godep
godep get -v ./...
```

- To update deps

```
rm -rf vendor GoDeps
go get -u github.com/tools/godep
godep save -d -v ./..
git add vendor GoDeps
```
