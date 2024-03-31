import json
import datetime
import requests

# Assuming jsonData is a list of JSON objects
jsonData = [
    {
        "blockNumber": "18412048",
        "timeStamp": "1698052979",
        "hash": "0xc92778132be53780983c080de8d874b05b7579ef854bc144423c33531738770d",
        "nonce": "3",
        "blockHash": "0x513bf64da7c755697db6bb606fbefa248f462d499f44e0931c686080d1fa2b4f",
        "transactionIndex": "17",
        "from": "0xa6462ffbd9ca38f1267e1323218d024f2d19145f",
        "to": "0xd740806a02e78aba46111750be296522e4cdb228",
        "value": "0",
        "gas": "52608",
        "gasPrice": "11649797765",
        "isError": "0",
        "txreceipt_status": "1",
        "input": "0xa9059cbb0000000000000000000000008643be1f1055a7f0daf832da2a5f6141d1920ff70000000000000000000000000000000000000000000000056bc75e2d63100000",
        "contractAddress": "",
        "cumulativeGasUsed": "3020160",
        "gasUsed": "35072",
        "confirmations": "1139345",
        "methodId": "0xa9059cbb",
        "functionName": "transfer(address _to, uint256 _value)"
    },
    {
        "blockNumber": "18411350",
        "timeStamp": "1698044399",
        "hash": "0xe694a47ea952e0a9e5dec808a78f2385266faacc4093915839d57ad7387323d1",
        "nonce": "2",
        "blockHash": "0x52d322d380e2484ba76ce5a2cc965d574769c40a1f985ffaa54f865f727d6078",
        "transactionIndex": "33",
        "from": "0xa6462ffbd9ca38f1267e1323218d024f2d19145f",
        "to": "0xd740806a02e78aba46111750be296522e4cdb228",
        "value": "0",
        "gas": "52626",
        "gasPrice": "8119929620",
        "isError": "0",
        "txreceipt_status": "1",
        "input": "0xa9059cbb0000000000000000000000008643be1f1055a7f0daf832da2a5f6141d1920ff700000000000000000000000000000000000000000000021e19e0c9bab2400000",
        "contractAddress": "",
        "cumulativeGasUsed": "5761290",
        "gasUsed": "35084",
        "confirmations": "1140043",
        "methodId": "0xa9059cbb",
        "functionName": "transfer(address _to, uint256 _value)"
    },
    {
        "blockNumber": "18411254",
        "timeStamp": "1698043235",
        "hash": "0x8b50d20b1ac97f6d0b0be16263539842b8d7b82d06d12b922fea5a6cb1cb3809",
        "nonce": "1",
        "blockHash": "0xb7ed090cc8583dc77faa7ab8db2dd7537b111c820f146b4d8198798dced16587",
        "transactionIndex": "59",
        "from": "0xa6462ffbd9ca38f1267e1323218d024f2d19145f",
        "to": "0xd740806a02e78aba46111750be296522e4cdb228",
        "value": "0",
        "gas": "78258",
        "gasPrice": "8310320276",
        "isError": "0",
        "txreceipt_status": "1",
        "input": "0xa9059cbb0000000000000000000000008643be1f1055a7f0daf832da2a5f6141d1920ff700000000000000000000000000000000000000000000003635c9adc5dea00000",
        "contractAddress": "",
        "cumulativeGasUsed": "5750307",
        "gasUsed": "52172",
        "confirmations": "1140139",
        "methodId": "0xa9059cbb",
        "functionName": "transfer(address _to, uint256 _value)"
    },
    {
        "blockNumber": "18318287",
        "timeStamp": "1696919579",
        "hash": "0x8762d4779124101fc6154810e0fe8e1e00d1bff7abd7aa2e5fcccf666ecddfbd",
        "nonce": "0",
        "blockHash": "0x5a6dbdce06765651a38a9dfb69d2120ae96617ad2777030f5ab0e28731f0e5d0",
        "transactionIndex": "50",
        "from": "0xa6462ffbd9ca38f1267e1323218d024f2d19145f",
        "to": "",
        "value": "0",
        "gas": "1710601",
        "gasPrice": "5365096291",
        "isError": "0",
        "txreceipt_status": "1",
        "input": "0x61016060405234801562000011575f80fd5b506040518060400160405280600881526020017f5353505f434f494e000000000000000000000000000000000000000000000000815250806040518060400160405280600181526020017f31000000000000000000000000000000000000000000000000000000000000008152506040518060400160405280600881526020017f5353505f434f494e0000000000000000000000000000000000000000000000008152506040518060400160405280600381526020017f53535000000000000000000000000000000000000000000000000000000000008152508160039081620000fc919062000846565b5080600490816200010e919062000846565b505050620001276005836200020860201b90919060201c565b6101208181525050620001456006826200020860201b90919060201c565b6101408181525050818051906020012060e08181525050808051906020012061010081815250504660a08181525050620001846200025d60201b60201c565b608081815250503073ffffffffffffffffffffffffffffffffffffffff1660c08173ffffffffffffffffffffffffffffffffffffffff16815250505050506200020233620001d7620002b960201b60201c565b600a620001e5919062000ab3565b6308f0d180620001f6919062000b03565b620002c160201b60201c565b62000e0b565b5f6020835110156200022d5762000225836200034b60201b60201c565b905062000257565b826200023f83620003b560201b60201c565b5f0190816200024f919062000846565b5060ff5f1b90505b92915050565b5f7f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f60e0516101005146306040516020016200029e95949392919062000bbb565b60405160208183030381529060405280519060200120905090565b5f6012905090565b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff160362000334575f6040517fec442f050000000000000000000000000000000000000000000000000000000081526004016200032b919062000c16565b60405180910390fd5b620003475f8383620003be60201b60201c565b5050565b5f80829050601f815111156200039a57826040517f305a27a900000000000000000000000000000000000000000000000000000000815260040162000391919062000cbb565b60405180910390fd5b805181620003a89062000d0c565b5f1c175f1b915050919050565b5f819050919050565b5f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff160362000412578060025f82825462000405919062000d7b565b92505081905550620004e3565b5f805f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20549050818110156200049e578381836040517fe450d38c000000000000000000000000000000000000000000000000000000008152600401620004959392919062000db5565b60405180910390fd5b8181035f808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2081905550505b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16036200052c578060025f828254039250508190555062000576565b805f808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825401925050819055505b8173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef83604051620005d5919062000df0565b60405180910390a3505050565b5f81519050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f60028204905060018216806200065e57607f821691505b60208210810362000674576200067362000619565b5b50919050565b5f819050815f5260205f209050919050565b5f6020601f8301049050919050565b5f82821b905092915050565b5f60088302620006d87fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff826200069b565b620006e486836200069b565b95508019841693508086168417925050509392505050565b5f819050919050565b5f819050919050565b5f6200072e620007286200072284620006fc565b62000705565b620006fc565b9050919050565b5f819050919050565b62000749836200070e565b62000761620007588262000735565b848454620006a7565b825550505050565b5f90565b6200077762000769565b620007848184846200073e565b505050565b5b81811015620007ab576200079f5f826200076d565b6001810190506200078a565b5050565b601f821115620007fa57620007c4816200067a565b620007cf846200068c565b81016020851015620007df578190505b620007f7620007ee856200068c565b83018262000789565b50505b505050565b5f82821c905092915050565b5f6200081c5f1984600802620007ff565b1980831691505092915050565b5f6200083683836200080b565b9150826002028217905092915050565b6200085182620005e2565b67ffffffffffffffff8111156200086d576200086c620005ec565b5b62000879825462000646565b62000886828285620007af565b5f60209050601f831160018114620008bc575f8415620008a7578287015190505b620008b3858262000829565b86555062000922565b601f198416620008cc866200067a565b5f5b82811015620008f557848901518255600182019150602085019450602081019050620008ce565b8683101562000915578489015162000911601f8916826200080b565b8355505b6001600288020188555050505b505050505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f8160011c9050919050565b5f808291508390505b6001851115620009b4578086048111156200098c576200098b6200092a565b5b60018516156200099c5780820291505b8081029050620009ac8562000957565b94506200096c565b94509492505050565b5f82620009ce576001905062000aa0565b81620009dd575f905062000aa0565b8160018114620009f6576002811462000a015762000a37565b600191505062000aa0565b60ff84111562000a165762000a156200092a565b5b8360020a91508482111562000a305762000a2f6200092a565b5b5062000aa0565b5060208310610133831016604e8410600b841016171562000a715782820a90508381111562000a6b5762000a6a6200092a565b5b62000aa0565b62000a80848484600162000963565b9250905081840481111562000a9a5762000a996200092a565b5b81810290505b9392505050565b5f60ff82169050919050565b5f62000abf82620006fc565b915062000acc8362000aa7565b925062000afb7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8484620009bd565b905092915050565b5f62000b0f82620006fc565b915062000b1c83620006fc565b925082820262000b2c81620006fc565b9150828204841483151762000b465762000b456200092a565b5b5092915050565b5f819050919050565b62000b618162000b4d565b82525050565b62000b7281620006fc565b82525050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f62000ba38262000b78565b9050919050565b62000bb58162000b97565b82525050565b5f60a08201905062000bd05f83018862000b56565b62000bdf602083018762000b56565b62000bee604083018662000b56565b62000bfd606083018562000b67565b62000c0c608083018462000baa565b9695505050505050565b5f60208201905062000c2b5f83018462000baa565b92915050565b5f82825260208201905092915050565b5f5b8381101562000c6057808201518184015260208101905062000c43565b5f8484015250505050565b5f601f19601f8301169050919050565b5f62000c8782620005e2565b62000c93818562000c31565b935062000ca581856020860162000c41565b62000cb08162000c6b565b840191505092915050565b5f6020820190508181035f83015262000cd5818462000c7b565b905092915050565b5f81519050919050565b5f819050602082019050919050565b5f62000d03825162000b4d565b80915050919050565b5f62000d188262000cdd565b8262000d248462000ce7565b905062000d318162000cf6565b9250602082101562000d745762000d6f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff836020036008026200069b565b831692505b5050919050565b5f62000d8782620006fc565b915062000d9483620006fc565b925082820190508082111562000daf5762000dae6200092a565b5b92915050565b5f60608201905062000dca5f83018662000baa565b62000dd9602083018562000b67565b62000de8604083018462000b67565b949350505050565b5f60208201905062000e055f83018462000b67565b92915050565b60805160a05160c05160e051610100516101205161014051611b6e62000e5d5f395f610a1501525f6109da01525f610f0e01525f610eed01525f6108d801525f61092e01525f6109570152611b6e5ff3fe608060405234801561000f575f80fd5b50600436106100cd575f3560e01c806370a082311161008a57806395d89b411161006457806395d89b411461022d578063a9059cbb1461024b578063d505accf1461027b578063dd62ed3e14610297576100cd565b806370a08231146101a95780637ecebe00146101d957806384b0196e14610209576100cd565b806306fdde03146100d1578063095ea7b3146100ef57806318160ddd1461011f57806323b872dd1461013d578063313ce5671461016d5780633644e5151461018b575b5f80fd5b6100d96102c7565b6040516100e691906113de565b60405180910390f35b6101096004803603810190610104919061148f565b610357565b60405161011691906114e7565b60405180910390f35b610127610379565b604051610134919061150f565b60405180910390f35b61015760048036038101906101529190611528565b610382565b60405161016491906114e7565b60405180910390f35b6101756103b0565b6040516101829190611593565b60405180910390f35b6101936103b8565b6040516101a091906115c4565b60405180910390f35b6101c360048036038101906101be91906115dd565b6103c6565b6040516101d0919061150f565b60405180910390f35b6101f360048036038101906101ee91906115dd565b61040b565b604051610200919061150f565b60405180910390f35b61021161041c565b6040516102249796959493929190611708565b60405180910390f35b6102356104c1565b60405161024291906113de565b60405180910390f35b6102656004803603810190610260919061148f565b610551565b60405161027291906114e7565b60405180910390f35b610295600480360381019061029091906117de565b610573565b005b6102b160048036038101906102ac919061187b565b6106b8565b6040516102be919061150f565b60405180910390f35b6060600380546102d6906118e6565b80601f0160208091040260200160405190810160405280929190818152602001828054610302906118e6565b801561034d5780601f106103245761010080835404028352916020019161034d565b820191905f5260205f20905b81548152906001019060200180831161033057829003601f168201915b5050505050905090565b5f8061036161073a565b905061036e818585610741565b600191505092915050565b5f600254905090565b5f8061038c61073a565b9050610399858285610753565b6103a48585856107e5565b60019150509392505050565b5f6012905090565b5f6103c16108d5565b905090565b5f805f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20549050919050565b5f6104158261098b565b9050919050565b5f6060805f805f606061042d6109d1565b610435610a0c565b46305f801b5f67ffffffffffffffff81111561045457610453611916565b5b6040519080825280602002602001820160405280156104825781602001602082028036833780820191505090505b507f0f00000000000000000000000000000000000000000000000000000000000000959493929190965096509650965096509650965090919293949596565b6060600480546104d0906118e6565b80601f01602080910402602001604051908101604052809291908181526020018280546104fc906118e6565b80156105475780601f1061051e57610100808354040283529160200191610547565b820191905f5260205f20905b81548152906001019060200180831161052a57829003601f168201915b5050505050905090565b5f8061055b61073a565b90506105688185856107e5565b600191505092915050565b834211156105b857836040517f627913020000000000000000000000000000000000000000000000000000000081526004016105af919061150f565b60405180910390fd5b5f7f6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c98888886105e68c610a47565b896040516020016105fc96959493929190611943565b6040516020818303038152906040528051906020012090505f61061e82610a9a565b90505f61062d82878787610ab3565b90508973ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16146106a157808a6040517f4b800e460000000000000000000000000000000000000000000000000000000081526004016106989291906119a2565b60405180910390fd5b6106ac8a8a8a610741565b50505050505050505050565b5f60015f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2054905092915050565b5f33905090565b61074e8383836001610ae1565b505050565b5f61075e84846106b8565b90507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81146107df57818110156107d0578281836040517ffb8f41b20000000000000000000000000000000000000000000000000000000081526004016107c7939291906119c9565b60405180910390fd5b6107de84848484035f610ae1565b5b50505050565b5f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1603610855575f6040517f96c6fd1e00000000000000000000000000000000000000000000000000000000815260040161084c91906119fe565b60405180910390fd5b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16036108c5575f6040517fec442f050000000000000000000000000000000000000000000000000000000081526004016108bc91906119fe565b60405180910390fd5b6108d0838383610cb0565b505050565b5f7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff163073ffffffffffffffffffffffffffffffffffffffff1614801561095057507f000000000000000000000000000000000000000000000000000000000000000046145b1561097d577f00000000000000000000000000000000000000000000000000000000000000009050610988565b610985610ec9565b90505b90565b5f60075f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20549050919050565b6060610a0760057f0000000000000000000000000000000000000000000000000000000000000000610f5e90919063ffffffff16565b905090565b6060610a4260067f0000000000000000000000000000000000000000000000000000000000000000610f5e90919063ffffffff16565b905090565b5f60075f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f815480929190600101919050559050919050565b5f610aac610aa66108d5565b8361100b565b9050919050565b5f805f80610ac38888888861104b565b925092509250610ad38282611132565b829350505050949350505050565b5f73ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff1603610b51575f6040517fe602df05000000000000000000000000000000000000000000000000000000008152600401610b4891906119fe565b60405180910390fd5b5f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1603610bc1575f6040517f94280d62000000000000000000000000000000000000000000000000000000008152600401610bb891906119fe565b60405180910390fd5b8160015f8673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20819055508015610caa578273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92584604051610ca1919061150f565b60405180910390a35b50505050565b5f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1603610d00578060025f828254610cf49190611a44565b92505081905550610dce565b5f805f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2054905081811015610d89578381836040517fe450d38c000000000000000000000000000000000000000000000000000000008152600401610d80939291906119c9565b60405180910390fd5b8181035f808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2081905550505b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603610e15578060025f8282540392505081905550610e5f565b805f808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825401925050819055505b8173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef83604051610ebc919061150f565b60405180910390a3505050565b5f7f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f7f00000000000000000000000000000000000000000000000000000000000000007f00000000000000000000000000000000000000000000000000000000000000004630604051602001610f43959493929190611a77565b60405160208183030381529060405280519060200120905090565b606060ff5f1b8314610f7a57610f7383611294565b9050611005565b818054610f86906118e6565b80601f0160208091040260200160405190810160405280929190818152602001828054610fb2906118e6565b8015610ffd5780601f10610fd457610100808354040283529160200191610ffd565b820191905f5260205f20905b815481529060010190602001808311610fe057829003601f168201915b505050505090505b92915050565b5f6040517f190100000000000000000000000000000000000000000000000000000000000081528360028201528260228201526042812091505092915050565b5f805f7f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0845f1c1115611087575f600385925092509250611128565b5f6001888888886040515f81526020016040526040516110aa9493929190611ac8565b6020604051602081039080840390855afa1580156110ca573d5f803e3d5ffd5b5050506020604051035190505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff160361111b575f60015f801b93509350935050611128565b805f805f1b935093509350505b9450945094915050565b5f600381111561114557611144611b0b565b5b82600381111561115857611157611b0b565b5b0315611290576001600381111561117257611171611b0b565b5b82600381111561118557611184611b0b565b5b036111bc576040517ff645eedf00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b600260038111156111d0576111cf611b0b565b5b8260038111156111e3576111e2611b0b565b5b0361122757805f1c6040517ffce698f700000000000000000000000000000000000000000000000000000000815260040161121e919061150f565b60405180910390fd5b60038081111561123a57611239611b0b565b5b82600381111561124d5761124c611b0b565b5b0361128f57806040517fd78bce0c00000000000000000000000000000000000000000000000000000000815260040161128691906115c4565b60405180910390fd5b5b5050565b60605f6112a083611306565b90505f602067ffffffffffffffff8111156112be576112bd611916565b5b6040519080825280601f01601f1916602001820160405280156112f05781602001600182028036833780820191505090505b5090508181528360208201528092505050919050565b5f8060ff835f1c169050601f81111561134b576040517fb3512b0c00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b80915050919050565b5f81519050919050565b5f82825260208201905092915050565b5f5b8381101561138b578082015181840152602081019050611370565b5f8484015250505050565b5f601f19601f8301169050919050565b5f6113b082611354565b6113ba818561135e565b93506113ca81856020860161136e565b6113d381611396565b840191505092915050565b5f6020820190508181035f8301526113f681846113a6565b905092915050565b5f80fd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f61142b82611402565b9050919050565b61143b81611421565b8114611445575f80fd5b50565b5f8135905061145681611432565b92915050565b5f819050919050565b61146e8161145c565b8114611478575f80fd5b50565b5f8135905061148981611465565b92915050565b5f80604083850312156114a5576114a46113fe565b5b5f6114b285828601611448565b92505060206114c38582860161147b565b9150509250929050565b5f8115159050919050565b6114e1816114cd565b82525050565b5f6020820190506114fa5f8301846114d8565b92915050565b6115098161145c565b82525050565b5f6020820190506115225f830184611500565b92915050565b5f805f6060848603121561153f5761153e6113fe565b5b5f61154c86828701611448565b935050602061155d86828701611448565b925050604061156e8682870161147b565b9150509250925092565b5f60ff82169050919050565b61158d81611578565b82525050565b5f6020820190506115a65f830184611584565b92915050565b5f819050919050565b6115be816115ac565b82525050565b5f6020820190506115d75f8301846115b5565b92915050565b5f602082840312156115f2576115f16113fe565b5b5f6115ff84828501611448565b91505092915050565b5f7fff0000000000000000000000000000000000000000000000000000000000000082169050919050565b61163c81611608565b82525050565b61164b81611421565b82525050565b5f81519050919050565b5f82825260208201905092915050565b5f819050602082019050919050565b6116838161145c565b82525050565b5f611694838361167a565b60208301905092915050565b5f602082019050919050565b5f6116b682611651565b6116c0818561165b565b93506116cb8361166b565b805f5b838110156116fb5781516116e28882611689565b97506116ed836116a0565b9250506001810190506116ce565b5085935050505092915050565b5f60e08201905061171b5f83018a611633565b818103602083015261172d81896113a6565b9050818103604083015261174181886113a6565b90506117506060830187611500565b61175d6080830186611642565b61176a60a08301856115b5565b81810360c083015261177c81846116ac565b905098975050505050505050565b61179381611578565b811461179d575f80fd5b50565b5f813590506117ae8161178a565b92915050565b6117bd816115ac565b81146117c7575f80fd5b50565b5f813590506117d8816117b4565b92915050565b5f805f805f805f60e0888a0312156117f9576117f86113fe565b5b5f6118068a828b01611448565b97505060206118178a828b01611448565b96505060406118288a828b0161147b565b95505060606118398a828b0161147b565b945050608061184a8a828b016117a0565b93505060a061185b8a828b016117ca565b92505060c061186c8a828b016117ca565b91505092959891949750929550565b5f8060408385031215611891576118906113fe565b5b5f61189e85828601611448565b92505060206118af85828601611448565b9150509250929050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f60028204905060018216806118fd57607f821691505b6020821081036119105761190f6118b9565b5b50919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b5f60c0820190506119565f8301896115b5565b6119636020830188611642565b6119706040830187611642565b61197d6060830186611500565b61198a6080830185611500565b61199760a0830184611500565b979650505050505050565b5f6040820190506119b55f830185611642565b6119c26020830184611642565b9392505050565b5f6060820190506119dc5f830186611642565b6119e96020830185611500565b6119f66040830184611500565b949350505050565b5f602082019050611a115f830184611642565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f611a4e8261145c565b9150611a598361145c565b9250828201905080821115611a7157611a70611a17565b5b92915050565b5f60a082019050611a8a5f8301886115b5565b611a9760208301876115b5565b611aa460408301866115b5565b611ab16060830185611500565b611abe6080830184611642565b9695505050505050565b5f608082019050611adb5f8301876115b5565b611ae86020830186611584565b611af560408301856115b5565b611b0260608301846115b5565b95945050505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602160045260245ffdfea2646970667358221220015a51a3ff9f940d76c7ad40d26f71dfc729d73d3a7e5190ea47698e9cc952e264736f6c63430008150033",
        "contractAddress": "0xd740806a02e78aba46111750be296522e4cdb228",
        "cumulativeGasUsed": "6381343",
        "gasUsed": "1710601",
        "confirmations": "1233106",
        "methodId": "0x61016060",
        "functionName": ""
    },
    {
        "blockNumber": "18318262",
        "timeStamp": "1696919279",
        "hash": "0xd00a584699e34d7e14d2c9ae53531bb68c3379d5ccf89eadf21a12ccfa70abd1",
        "nonce": "1",
        "blockHash": "0xe878113d3cf5005003aef5fdf067777216abb6e684b5c516b2da9040b21eb73d",
        "transactionIndex": "72",
        "from": "0x5bd4361343ffc2098563bed1a53dca155183a46b",
        "to": "0xa6462ffbd9ca38f1267e1323218d024f2d19145f",
        "value": "2300000000000000",
        "gas": "21000",
        "gasPrice": "5104835228",
        "isError": "0",
        "txreceipt_status": "1",
        "input": "0x",
        "contractAddress": "",
        "cumulativeGasUsed": "5778648",
        "gasUsed": "21000",
        "confirmations": "1233131",
        "methodId": "0x",
        "functionName": ""
    },
    {
        "blockNumber": "18283335",
        "timeStamp": "1696497131",
        "hash": "0x4dd963c274d7d86824632bfb71af15b09ebe751afa7e0558496d04f4371ac172",
        "nonce": "5243069",
        "blockHash": "0x7c8ec36a8a3d28283dc6e06b35841fc0c45b39cc199ede0e40faa658417f344e",
        "transactionIndex": "41",
        "from": "0x9696f59e4d72e237be84ffd425dcad154bf96976",
        "to": "0xa6462ffbd9ca38f1267e1323218d024f2d19145f",
        "value": "9981300000000000",
        "gas": "207128",
        "gasPrice": "9149992534",
        "isError": "0",
        "txreceipt_status": "1",
        "input": "0x",
        "contractAddress": "",
        "cumulativeGasUsed": "3878493",
        "gasUsed": "21000",
        "confirmations": "1268058",
        "methodId": "0x",
        "functionName": ""
    }
]

def Wei_to_Eth(amount):
    amount_is_wei = amount
    wei_to_ether_conversion_factor = 10 ** 18
    value_in_ether = amount_is_wei / wei_to_ether_conversion_factor
    return value_in_ether


def get_eth_to_usd_exchange_rate():
    url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
    response = requests.get(url)
    data = response.json()
    return data["ethereum"]["usd"]

# Loop through each JSON object
for data in jsonData:
    if data.get("from") == "0x5bd4361343ffc2098563bed1a53dca155183a46b":
        print("Received money!")
        user_address = data.get("from")
        timestamp_str = data.get('timeStamp')
        timestamp = int(timestamp_str)
        datetime_obj = datetime.datetime.utcfromtimestamp(timestamp)
        formatted_datetime = datetime_obj.strftime("%Y-%m-%d %H:%M:%S")
        eth_amount = data.get('value')
        eth_amount = int(eth_amount)
        eth_to_usd_exchange_rate = get_eth_to_usd_exchange_rate()
        usd_amount = eth_amount * eth_to_usd_exchange_rate
        usd_amount_formatted = "{:.2f}".format(usd_amount / 10**18)
        paymentId = data.get('blockNumber')
        value = int(data.get('value'))
        amount = Wei_to_Eth(value)
        original_amount_usd = 90.26
        userId = 23

        if original_amount_usd == float(usd_amount_formatted):
            status = "Complete"
        elif original_amount_usd < float(usd_amount_formatted):
            difference = float(usd_amount_formatted) - original_amount_usd
            status = f"OverPaid {difference:.2f}"
        elif original_amount_usd > float(usd_amount_formatted):
            difference = original_amount_usd - float(usd_amount_formatted)
            status = f"UnderPaid {difference:.2f}"
        else:
            status = "In Process"

        response = {
            "UserId":userId,
            "datetime": formatted_datetime,
            "paymentId": paymentId,
            "user_address": user_address,
            "amount": amount,
            "usd_amount": f"{usd_amount_formatted} USD",
            "status": status
        }
        print(response)
    else:
        print("Money not received for this entry.")







#
# timestamp = "1696497131"
# timestamp = int(timestamp)
# date_time = datetime.datetime.utcfromtimestamp(timestamp)
# print("Transaction Timestamp:", date_time)



