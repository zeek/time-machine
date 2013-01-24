/* This file is old and doesn't seem to use the current API */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <dirent.h>

#include "types.h"
#include "IndexField.hh"
#include "Index.hh"

void usage() {
	fprintf(stderr,
			"usage: tm_q [ -i index name ] [ -k key value ]\n"
			"            [ -n lower index number (decimal) ]\n"
			"            [ -N upper index number (decimal) ]\n"
			"            [ -o use old index file format ]\n"
		   );
	exit(1);
}

int filter_class_files(const struct dirent *d) {
	return ! strncmp(d->d_name, "class_", 6);
}


int main(int argc, char** argv) {
	char* index_type=NULL;
	char* str_key_value=NULL;
	int opt;
	uint32_t n0=1, n1=0xffffffff;
	int old_file_format=0;

	while ((opt=getopt(argc, argv, "i:k:hn:N:o")) != -1) {
		switch(opt) {
		case 'i':
			index_type=strdup(optarg);
			break;
		case 'k':
			str_key_value=strdup(optarg);
			break;
		case 'n':
			n0=atoi(optarg);
			break;
		case 'N':
			n1=atoi(optarg);
			break;
		case 'o':
			old_file_format=1;
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (!index_type || !str_key_value) usage();

	IndexField* key=NULL;
	DiskIndexReader<IndexField> r(index_type);

	if (!strcmp(index_type, "ip")) {
		//    uint32_t key=inet_addr(str_key_value);
		key=new IPAddress(str_key_value);
		//    r=new DiskIndexReader<IPAddress>(index_type);
	} else if(!strcmp(index_type, "port")) {
		key=new Port(atoi(str_key_value));
		//    r=new DiskIndexReader<Port>(index_type);
	} else if(!strcmp(index_type, "dstip")) {
		key=new DstIPAddress(str_key_value);
		//    r=new DiskIndexReader<Port>(index_type);
	} else if(!strcmp(index_type, "srcip")) {
		key=new SrcIPAddress(str_key_value);
		//    r=new DiskIndexReader<Port>(index_type);
	} else if(!strcmp(index_type, "dstport")) {
		key=new DstPort(atoi(str_key_value));
		//    r=new DiskIndexReader<Port>(index_type);
	} else if(!strcmp(index_type, "srcport")) {
		key=new SrcPort(atoi(str_key_value));
		//    r=new DiskIndexReader<Port>(index_type);
	} else if(!strcmp(index_type, "connection")) {
		uint8_t proto=atoi(strtok(str_key_value, "-"));
		IPAddress sip=IPAddress(strtok(NULL, ":"));
		uint16_t spt=atoi(strtok(NULL, "-"));
		IPAddress dip=IPAddress(strtok(NULL, ":"));
		uint16_t dpt=atoi(strtok(NULL, ""));

		std::cout << "parsed: " << proto << " "
		<< sip.getStr() << " " << spt << " "
		<< dip.getStr() << " " << dpt << std::endl;

		key=new ConnectionIF(proto, sip.getInt(), spt, dip.getInt(), dpt);
		//    r=new DiskIndexReader<Port>(index_type);
	} else {
		fprintf(stderr, "wrong index type %s\n", index_type);
		exit(1);
	}

	//  printf("%s\n", key->getIndexName().c_str());
	printf("key size %d\n", (*key).getKeySize());

	std::list<Interval> list=r.seek(key, n0, n1, old_file_format);

	for (std::list<Interval>::iterator i=list.begin(); i!=list.end(); i++) {
		const time_t t1=(time_t)i->getStart();
		const time_t t2=(time_t)i->getLast();
		char s1[80], s2[80];
		strftime(s1, 80, "%m/%d %H:%M:%S", localtime(&t1));
		strftime(s2, 80, "%H:%M:%S", localtime(&t2));
		printf("%f - %f (%s.%06d - %s.%06d)\n", i->getStart(), i->getLast(),
			   s1, (int)((i->getStart()-t1)*1000000),
			   s2, (int)((i->getLast()-t2)*1000000)
			  );

		/*
		struct dirent **namelist;
		int n;

		n = scandir(".", &namelist, filter, alphasort);
		if (n < 0)
		  perror("scandir");  
		else {
		  while(n--) {
		printf("%s\n", namelist[n]->d_name);
		free(namelist[n]);
		  }
		  free(namelist);
		}

		for (int f=0
		pcap_t ph=pcap_open_offline(
		*/

		//    printf("[%f,%f]\n", i->getStart(), i->getLast());
	}
	delete key;

}

