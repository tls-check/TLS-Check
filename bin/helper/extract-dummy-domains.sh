# perl -nE 'chomp; ($num, $domain) = split /,/; say "$domain;1"' ~/Downloads/top-1m-2015-06-14.csv  | perl  -MList::Util=shuffle -E 'print shuffle <>' | tail -n 1000 >dummy-domains-1000-a.csv

# perl -nE 'chomp; ($num, $domain) = split /,/; say "$domain;1" if $domain =~ m{de$};' ~/Downloads/top-1m-2015-06-14.csv  | perl  -MList::Util=shuffle -E 'print shuffle <>' | tail -n 1000 >dummy-de-domains-1000-b.csv




