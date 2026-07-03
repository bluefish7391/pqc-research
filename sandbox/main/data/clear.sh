main() {
    rm -rf ./collection_*/
    rm -rf ./figures/*

    echo "Data cleared."
}

main "$@"