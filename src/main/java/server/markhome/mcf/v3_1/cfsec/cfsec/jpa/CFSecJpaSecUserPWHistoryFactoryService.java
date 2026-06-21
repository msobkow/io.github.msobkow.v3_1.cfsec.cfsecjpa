
// Description: Java 25 Factory service implementation for SecUserPWHistory JPA objects

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.lang.reflect.*;
import java.net.*;
import java.rmi.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/*
 *	Java 25 Factory service implementation for SecUserPWHistory JPA objects.
 */
public class CFSecJpaSecUserPWHistoryFactoryService
    implements ICFSecSecUserPWHistoryFactory
{
    public CFSecJpaSecUserPWHistoryFactoryService() { }

    @Override
    public ICFSecSecUserPWHistoryPKey newPKey() {
        ICFSecSecUserPWHistoryPKey pkey = new CFSecJpaSecUserPWHistoryPKey();
        return( pkey );
    }

	public CFSecJpaSecUserPWHistoryPKey ensurePKey(ICFSecSecUserPWHistoryPKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecUserPWHistoryPKey) {
			return( (CFSecJpaSecUserPWHistoryPKey)key );
		}
		else {
			CFSecJpaSecUserPWHistoryPKey mapped = new CFSecJpaSecUserPWHistoryPKey();
			mapped.setRequiredSecUserId( key.getRequiredSecUserId() );
			mapped.setRequiredPWSetStamp( key.getRequiredPWSetStamp() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecUserPWHistoryByUserIdxKey newByUserIdxKey() {
		ICFSecSecUserPWHistoryByUserIdxKey key = new CFSecJpaSecUserPWHistoryByUserIdxKey();
	return( key );
    }

	public CFSecJpaSecUserPWHistoryByUserIdxKey ensureByUserIdxKey(ICFSecSecUserPWHistoryByUserIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecUserPWHistoryByUserIdxKey) {
			return( (CFSecJpaSecUserPWHistoryByUserIdxKey)key );
		}
		else {
			CFSecJpaSecUserPWHistoryByUserIdxKey mapped = new CFSecJpaSecUserPWHistoryByUserIdxKey();
			mapped.setRequiredSecUserId( key.getRequiredSecUserId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecUserPWHistoryBySetStampIdxKey newBySetStampIdxKey() {
		ICFSecSecUserPWHistoryBySetStampIdxKey key = new CFSecJpaSecUserPWHistoryBySetStampIdxKey();
	return( key );
    }

	public CFSecJpaSecUserPWHistoryBySetStampIdxKey ensureBySetStampIdxKey(ICFSecSecUserPWHistoryBySetStampIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecUserPWHistoryBySetStampIdxKey) {
			return( (CFSecJpaSecUserPWHistoryBySetStampIdxKey)key );
		}
		else {
			CFSecJpaSecUserPWHistoryBySetStampIdxKey mapped = new CFSecJpaSecUserPWHistoryBySetStampIdxKey();
			mapped.setRequiredPWSetStamp( key.getRequiredPWSetStamp() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecUserPWHistoryByReplacedStampIdxKey newByReplacedStampIdxKey() {
		ICFSecSecUserPWHistoryByReplacedStampIdxKey key = new CFSecJpaSecUserPWHistoryByReplacedStampIdxKey();
	return( key );
    }

	public CFSecJpaSecUserPWHistoryByReplacedStampIdxKey ensureByReplacedStampIdxKey(ICFSecSecUserPWHistoryByReplacedStampIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecUserPWHistoryByReplacedStampIdxKey) {
			return( (CFSecJpaSecUserPWHistoryByReplacedStampIdxKey)key );
		}
		else {
			CFSecJpaSecUserPWHistoryByReplacedStampIdxKey mapped = new CFSecJpaSecUserPWHistoryByReplacedStampIdxKey();
			mapped.setRequiredPWReplacedStamp( key.getRequiredPWReplacedStamp() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecUserPWHistory newRec() {
        ICFSecSecUserPWHistory rec = new CFSecJpaSecUserPWHistory();
        return( rec );
    }

	public CFSecJpaSecUserPWHistory ensureRec(ICFSecSecUserPWHistory rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecUserPWHistory) {
			return( (CFSecJpaSecUserPWHistory)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecSecUserPWHistory.CLASS_CODE: {
					CFSecJpaSecUserPWHistory mapped = new CFSecJpaSecUserPWHistory();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecUserPWHistory",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecUserPWHistory");
			}
		}
	}
}
