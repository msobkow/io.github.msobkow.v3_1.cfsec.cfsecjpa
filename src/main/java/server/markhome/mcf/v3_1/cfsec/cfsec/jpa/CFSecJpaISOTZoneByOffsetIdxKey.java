// Description: Java 25 JPA implementation of a ISOTZone by OffsetIdx index key object.

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

import java.io.Serializable;
import java.math.*;
import java.time.*;
import java.util.*;
import jakarta.persistence.*;
import jakarta.transaction.Transactional;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

public class CFSecJpaISOTZoneByOffsetIdxKey
	implements ICFSecISOTZoneByOffsetIdxKey, Comparable<Object>, Serializable
{
	protected $implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ requiredTZHourOffset;
	protected $implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ requiredTZMinOffset;
	public CFSecJpaISOTZoneByOffsetIdxKey() {
		requiredTZHourOffset = ICFSecPubISOTZone.TZHOUROFFSET_INIT_VALUE;
		requiredTZMinOffset = ICFSecPubISOTZone.TZMINOFFSET_INIT_VALUE;
	}

	@Override
	public $implIJavaAtomType$ getRequiredTZHourOffset() {
		return(requiredTZHourOffset);
	}

	@Override
	public void setRequiredTZHourOffset( $implIJavaAtomType$ value ) {
		if( value < ICFSecPubISOTZone.TZHOUROFFSET_MIN_VALUE ) {
			throw new CFLibArgumentUnderflowException( getClass(),
				"setRequiredTZHourOffset",
				1,
				"value",
				value,
				ICFSecPubISOTZone.TZHOUROFFSET_MIN_VALUE );
		}
		if( value > ICFSecPubISOTZone.TZHOUROFFSET_MAX_VALUE ) {
			throw new CFLibArgumentOverflowException( getClass(),
				"setRequiredTZHourOffset",
				1,
				"value",
				value,
				ICFSecPubISOTZone.TZHOUROFFSET_MAX_VALUE );
		}
		requiredTZHourOffset = value;
	}

	@Override
	public $implIJavaAtomType$ getRequiredTZMinOffset() {
		return(requiredTZMinOffset);
	}

	@Override
	public void setRequiredTZMinOffset( $implIJavaAtomType$ value ) {
		if( value < ICFSecPubISOTZone.TZMINOFFSET_MIN_VALUE ) {
			throw new CFLibArgumentUnderflowException( getClass(),
				"setRequiredTZMinOffset",
				1,
				"value",
				value,
				ICFSecPubISOTZone.TZMINOFFSET_MIN_VALUE );
		}
		if( value > ICFSecPubISOTZone.TZMINOFFSET_MAX_VALUE ) {
			throw new CFLibArgumentOverflowException( getClass(),
				"setRequiredTZMinOffset",
				1,
				"value",
				value,
				ICFSecPubISOTZone.TZMINOFFSET_MAX_VALUE );
		}
		requiredTZMinOffset = value;
	}

	@Override
	public boolean equals( Object obj ) {
		if (obj == null) {
			return( false );
		}
		else if (obj instanceof ICFSecISOTZoneByOffsetIdxKey) {
			ICFSecISOTZoneByOffsetIdxKey rhs = (ICFSecISOTZoneByOffsetIdxKey)obj;
			if( getRequiredTZHourOffset() != rhs.getRequiredTZHourOffset() ) {
				return( false );
			}
			if( getRequiredTZMinOffset() != rhs.getRequiredTZMinOffset() ) {
				return( false );
			}
			return( true );
		}
		else if (obj instanceof ICFSecISOTZone) {
			ICFSecISOTZone rhs = (ICFSecISOTZone)obj;
			if( getRequiredTZHourOffset() != rhs.getRequiredTZHourOffset() ) {
				return( false );
			}
			if( getRequiredTZMinOffset() != rhs.getRequiredTZMinOffset() ) {
				return( false );
			}
			return( true );
		}
		else if (obj instanceof ICFSecISOTZoneH) {
			ICFSecISOTZoneH rhs = (ICFSecISOTZoneH)obj;
			if( getRequiredTZHourOffset() != rhs.getRequiredTZHourOffset() ) {
				return( false );
			}
			if( getRequiredTZMinOffset() != rhs.getRequiredTZMinOffset() ) {
				return( false );
			}
			return( true );
		}
		else {
			return( false );
		}
	}

	@Override
	public int hashCode() {
		int hashCode = 0;
		hashCode = ( hashCode * 0x10000 ) + getRequiredTZHourOffset();
		hashCode = ( hashCode * 0x10000 ) + getRequiredTZMinOffset();
		return( hashCode & 0x7fffffff );
	}

	@Override
	public int compareTo( Object obj ) {
		int cmp;
		if (obj == null) {
			return( 1 );
		}
		else if (obj instanceof ICFSecISOTZoneByOffsetIdxKey) {
			ICFSecISOTZoneByOffsetIdxKey rhs = (ICFSecISOTZoneByOffsetIdxKey)obj;
			if( getRequiredTZHourOffset() < rhs.getRequiredTZHourOffset() ) {
				return( -1 );
			}
			else if( getRequiredTZHourOffset() > rhs.getRequiredTZHourOffset() ) {
				return( 1 );
			}
			if( getRequiredTZMinOffset() < rhs.getRequiredTZMinOffset() ) {
				return( -1 );
			}
			else if( getRequiredTZMinOffset() > rhs.getRequiredTZMinOffset() ) {
				return( 1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecISOTZone) {
			ICFSecISOTZone rhs = (ICFSecISOTZone)obj;
			if( getRequiredTZHourOffset() < rhs.getRequiredTZHourOffset() ) {
				return( -1 );
			}
			else if( getRequiredTZHourOffset() > rhs.getRequiredTZHourOffset() ) {
				return( 1 );
			}
			if( getRequiredTZMinOffset() < rhs.getRequiredTZMinOffset() ) {
				return( -1 );
			}
			else if( getRequiredTZMinOffset() > rhs.getRequiredTZMinOffset() ) {
				return( 1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecISOTZoneH) {
			ICFSecISOTZoneH rhs = (ICFSecISOTZoneH)obj;
			if( getRequiredTZHourOffset() < rhs.getRequiredTZHourOffset() ) {
				return( -1 );
			}
			else if( getRequiredTZHourOffset() > rhs.getRequiredTZHourOffset() ) {
				return( 1 );
			}
			if( getRequiredTZMinOffset() < rhs.getRequiredTZMinOffset() ) {
				return( -1 );
			}
			else if( getRequiredTZMinOffset() > rhs.getRequiredTZMinOffset() ) {
				return( 1 );
			}
			return( 0 );
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(),
				"compareTo",
				"obj",
				obj,
				"ICFSecISOTZoneByOffsetIdxKey, ICFSecISOTZone, ICFSecISOTZoneH");
		}
	}

	public String getXmlAttrFragment() {
		String ret = "" 
			+ " RequiredTZHourOffset=" + "\"" + Short.toString( getRequiredTZHourOffset() ) + "\""
			+ " RequiredTZMinOffset=" + "\"" + Short.toString( getRequiredTZMinOffset() ) + "\"";
		return( ret );
	}

	@Override
	public String toString() {
		String ret = "<CFSecISOTZoneByOffsetIdxKey" + getXmlAttrFragment() + "/>";
		return( ret );
	}
}
